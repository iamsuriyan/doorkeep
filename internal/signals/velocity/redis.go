package velocity

import (
	"context"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis implements Counter on Redis so every cluster node sees the same
// velocity. Counts use 10-second bucket counters (INCR + EXPIRE); distinct
// members use one HyperLogLog per bucket and member prefix, and PFCOUNT over
// a window's buckets gives the union cardinality. Keys are already
// pseudonymous; raw IP keys expire within an hour like the in-process
// tracker. If Redis is unreachable, counts read as zero (fail open) and the
// error is logged at most once a minute.
type Redis struct {
	c       *redis.Client
	prefix  string
	now     func() time.Time
	log     *slog.Logger
	lastErr atomic.Int64
}

// NewRedis connects using a redis:// URL.
func NewRedis(url string, now func() time.Time, log *slog.Logger) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	r := &Redis{c: redis.NewClient(opt), prefix: "dk:", now: now, log: log}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r, r.c.Ping(ctx).Err()
}

const opTimeout = 100 * time.Millisecond

func (r *Redis) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

func (r *Redis) fail(err error) {
	if err == nil || r.log == nil {
		return
	}
	now := time.Now().Unix()
	if last := r.lastErr.Load(); now-last >= 60 && r.lastErr.CompareAndSwap(last, now) {
		r.log.Warn("velocity: redis unavailable, counting as zero", "err", err)
	}
}

func bucketOf(t time.Time) int64 { return t.UnixNano() / int64(bucket) }

func memberPrefix(m string) string {
	if i := strings.IndexByte(m, ':'); i >= 0 {
		return m[:i+1]
	}
	return ""
}

func (r *Redis) Add(key string, members ...string) {
	ctx, cancel := r.ctx()
	defer cancel()
	b := strconv.FormatInt(bucketOf(r.now()), 10)
	ttl := time.Hour + 2*bucket
	p := r.c.Pipeline()
	ck := r.prefix + "c:" + key + ":" + b
	p.Incr(ctx, ck)
	p.Expire(ctx, ck, ttl)
	for _, m := range members {
		if m == "" {
			continue
		}
		hk := r.prefix + "h:" + key + ":" + memberPrefix(m) + ":" + b
		p.PFAdd(ctx, hk, m)
		p.Expire(ctx, hk, ttl)
	}
	tk := r.prefix + "t:" + key
	p.LPush(ctx, tk, r.now().UnixMilli())
	p.LTrim(ctx, tk, 0, 31)
	p.Expire(ctx, tk, ttl)
	_, err := p.Exec(ctx)
	r.fail(err)
}

func (r *Redis) bucketKeys(kind, key, sub string, d time.Duration) []string {
	span := int64(d / bucket)
	if span < 1 {
		span = 1
	}
	now := bucketOf(r.now())
	keys := make([]string, 0, span)
	for i := int64(0); i < span; i++ {
		k := r.prefix + kind + ":" + key
		if sub != "" {
			k += ":" + sub
		}
		keys = append(keys, k+":"+strconv.FormatInt(now-i, 10))
	}
	return keys
}

func (r *Redis) Count(key string, d time.Duration) int {
	ctx, cancel := r.ctx()
	defer cancel()
	vals, err := r.c.MGet(ctx, r.bucketKeys("c", key, "", d)...).Result()
	if err != nil {
		r.fail(err)
		return 0
	}
	total := 0
	for _, v := range vals {
		if s, ok := v.(string); ok {
			n, _ := strconv.Atoi(s)
			total += n
		}
	}
	return total
}

func (r *Redis) Distinct(key string, d time.Duration, prefix string) int {
	ctx, cancel := r.ctx()
	defer cancel()
	n, err := r.c.PFCount(ctx, r.bucketKeys("h", key, prefix, d)...).Result()
	if err != nil {
		r.fail(err)
		return 0
	}
	return int(n)
}

func (r *Redis) IntervalCV(key string) float64 {
	ctx, cancel := r.ctx()
	defer cancel()
	vals, err := r.c.LRange(ctx, r.prefix+"t:"+key, 0, -1).Result()
	if err != nil || len(vals) < 10 {
		r.fail(err)
		return math.NaN()
	}
	var n, mean, m2 float64
	for i := 1; i < len(vals); i++ {
		a, _ := strconv.ParseFloat(vals[i-1], 64)
		b, _ := strconv.ParseFloat(vals[i], 64)
		x := a - b // newest first
		n++
		dd := x - mean
		mean += dd / n
		m2 += dd * (x - mean)
	}
	if mean == 0 || n < 2 {
		return 0
	}
	return math.Sqrt(m2/(n-1)) / mean
}

// Len is not tracked in Redis; returns -1.
func (r *Redis) Len() int { return -1 }

// Close closes the client.
func (r *Redis) Close() error { return r.c.Close() }

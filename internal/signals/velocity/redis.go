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
// velocity. Counts use 10-second bucket counters (INCR + EXPIRE) plus
// per-minute counters; distinct members use HyperLogLogs at the same two
// granularities, and PFCOUNT over a window's keys gives the union
// cardinality. A window reads whole minutes from the minute keys and only
// its partial edges from the 10-second keys, so an hour is about 70 keys,
// not 360, and results match the in-process tracker exactly.
//
// Every Add is mirrored into an in-process Tracker. If Redis is unreachable,
// reads fall back to that node-local view (degraded: per node rather than
// cluster-wide) instead of reading as zero, so session rate limits and
// velocity rules keep working. The error is logged at most once a minute.
type Redis struct {
	c       *redis.Client
	prefix  string
	now     func() time.Time
	log     *slog.Logger
	local   *Tracker
	lastErr atomic.Int64
	errs    atomic.Uint64
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
	r := &Redis{c: redis.NewClient(opt), prefix: "dk:", now: now, log: log, local: New(now)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r, r.c.Ping(ctx).Err()
}

const (
	opTimeout       = 150 * time.Millisecond
	bucketsPerMin   = int64(time.Minute / bucket)
	redisTTL        = time.Hour + 2*time.Minute
	minuteKeyMarker = "m"
)

func (r *Redis) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

func (r *Redis) fail(err error) {
	if err == nil {
		return
	}
	r.errs.Add(1)
	if r.log == nil {
		return
	}
	now := time.Now().Unix()
	if last := r.lastErr.Load(); now-last >= 60 && r.lastErr.CompareAndSwap(last, now) {
		r.log.Warn("velocity: redis unavailable, using this node's counts only", "err", err)
	}
}

// Errors returns how many Redis calls have failed (for metrics).
func (r *Redis) Errors() uint64 { return r.errs.Load() }

// Local returns the node-local mirror (used for sweeping its memory).
func (r *Redis) Local() *Tracker { return r.local }

func bucketOf(t time.Time) int64 { return t.UnixNano() / int64(bucket) }

func memberPrefix(m string) string {
	if i := strings.IndexByte(m, ':'); i >= 0 {
		return m[:i+1]
	}
	return ""
}

// queueAdd appends one Add's commands to the pipeline.
func (r *Redis) queueAdd(ctx context.Context, p redis.Pipeliner, key string, members []string, b int64, nowMS int64) {
	bs := strconv.FormatInt(b, 10)
	ms := minuteKeyMarker + strconv.FormatInt(b/bucketsPerMin, 10)
	for _, suffix := range []string{bs, ms} {
		ck := r.prefix + "c:" + key + ":" + suffix
		p.Incr(ctx, ck)
		p.Expire(ctx, ck, redisTTL)
		for _, m := range members {
			if m == "" {
				continue
			}
			hk := r.prefix + "h:" + key + ":" + memberPrefix(m) + ":" + suffix
			p.PFAdd(ctx, hk, m)
			p.Expire(ctx, hk, redisTTL)
		}
	}
	tk := r.prefix + "t:" + key
	p.LPush(ctx, tk, nowMS)
	p.LTrim(ctx, tk, 0, 31)
	p.Expire(ctx, tk, redisTTL)
}

func (r *Redis) Add(key string, members ...string) {
	r.Batch([]Op{{Key: key, Members: members}}, nil)
}

// windowKeys lists the keys covering the 10-second buckets (now-span, now]:
// whole minutes as minute keys, partial minutes as bucket keys.
func (r *Redis) windowKeys(kind, key, sub string, d time.Duration) []string {
	span := int64(d / bucket)
	if span < 1 {
		span = 1
	}
	hi := bucketOf(r.now())
	lo := hi - span + 1
	base := r.prefix + kind + ":" + key + ":"
	if sub != "" {
		base += sub + ":"
	}
	keys := make([]string, 0, 2*bucketsPerMin+span/bucketsPerMin)
	for i := lo; i <= hi; {
		if i%bucketsPerMin == 0 && i+bucketsPerMin-1 <= hi {
			keys = append(keys, base+minuteKeyMarker+strconv.FormatInt(i/bucketsPerMin, 10))
			i += bucketsPerMin
			continue
		}
		keys = append(keys, base+strconv.FormatInt(i, 10))
		i++
	}
	return keys
}

// Batch sends all adds and reads in one pipeline (one round trip).
func (r *Redis) Batch(ops []Op, qs []Query) []int {
	local := r.local.Batch(ops, qs)
	ctx, cancel := r.ctx()
	defer cancel()
	p := r.c.Pipeline()
	now := r.now()
	b, nowMS := bucketOf(now), now.UnixMilli()
	for _, o := range ops {
		r.queueAdd(ctx, p, o.Key, o.Members, b, nowMS)
	}
	counts := make([]*redis.SliceCmd, len(qs))
	distinct := make([]*redis.IntCmd, len(qs))
	for i, q := range qs {
		if q.Prefix == "" {
			counts[i] = p.MGet(ctx, r.windowKeys("c", q.Key, "", q.Dur)...)
		} else {
			distinct[i] = p.PFCount(ctx, r.windowKeys("h", q.Key, q.Prefix, q.Dur)...)
		}
	}
	if _, err := p.Exec(ctx); err != nil && err != redis.Nil {
		r.fail(err)
		return local
	}
	out := make([]int, len(qs))
	for i := range qs {
		if counts[i] != nil {
			total := 0
			for _, v := range counts[i].Val() {
				if s, ok := v.(string); ok {
					n, _ := strconv.Atoi(s)
					total += n
				}
			}
			out[i] = total
		} else {
			out[i] = int(distinct[i].Val())
		}
	}
	return out
}

func (r *Redis) Count(key string, d time.Duration) int {
	return r.Batch(nil, []Query{{Key: key, Dur: d}})[0]
}

func (r *Redis) Distinct(key string, d time.Duration, prefix string) int {
	return r.Batch(nil, []Query{{Key: key, Dur: d, Prefix: prefix}})[0]
}

func (r *Redis) IntervalCV(key string) float64 {
	ctx, cancel := r.ctx()
	defer cancel()
	vals, err := r.c.LRange(ctx, r.prefix+"t:"+key, 0, -1).Result()
	if err != nil {
		r.fail(err)
		return r.local.IntervalCV(key)
	}
	if len(vals) < 10 {
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

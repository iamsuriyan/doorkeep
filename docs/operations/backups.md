# Backups

## Single node (SQLite)

```sh
doorkeep backup --out /backups/doorkeep-$(date +%F).tar.gz
```

The archive holds a consistent snapshot of the database (taken with SQLite's
`VACUUM INTO`, safe while doorkeep is serving) and the generated secrets
(`instance.secret`, `token.key`). **It contains the instance secret: store it
like a password.** IP intelligence is not included; it is re-downloaded.

Restore into an empty data directory (stop doorkeep first):

```sh
doorkeep restore --in doorkeep-2026-10-23.tar.gz        # refuses to overwrite a database
doorkeep restore --in doorkeep-2026-10-23.tar.gz --force
doorkeep ipdata update
```

Restore checks the archive (only the known files, no paths outside the data
directory), opens the database to run any newer migrations, and reports the
sites it found. Tokens issued before the backup stay valid only if the
secrets are restored with it.

A daily backup with systemd (create `/var/backups/doorkeep` first, mode
0700):

```ini
# /etc/systemd/system/doorkeep-backup.service
# Same dynamic user and state directory as deploy/systemd/doorkeep.service.
[Service]
Type=oneshot
DynamicUser=yes
User=doorkeep
StateDirectory=doorkeep
UMask=0077
ReadWritePaths=/var/backups/doorkeep
Environment=DOORKEEP_DATA_DIR=/var/lib/doorkeep
ExecStart=/bin/sh -c '/usr/local/bin/doorkeep backup --out /var/backups/doorkeep/doorkeep-$(date +%%F).tar.gz'
# /etc/systemd/system/doorkeep-backup.timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

## Cluster (Postgres)

`doorkeep backup` refuses in cluster mode. Back up Postgres with `pg_dump`
(or your provider's snapshots), and keep `DOORKEEP_SECRET` and
`DOORKEEP_TOKEN_KEY` in your secret store: without them, stored hashes cannot
be linked to new traffic and old tokens cannot be verified.

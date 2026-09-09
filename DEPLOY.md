# Deploying the reseed39 bloom server (oniric)

Public HTTPS/WSS endpoint. TLS is terminated by **stunnel**; behind it the bloom `server`
runs unprivileged on `127.0.0.1:8080`, serving both the reseed39 bundle (static) and the
WebSocket query API on the same origin. The seed never leaves the browser -- only derived
public addresses are sent, and the server only ever answers HIT/miss.

```
internet :443  --TLS-->  stunnel  --plaintext-->  127.0.0.1:8080  server (WS + static)
```

## Layout on the box (`/home/ubuntu/reseed39/`)
- `server`                 -- static x86-64 binary (built off-box; no toolchain needed here)
- `alladdrs_classic.blf`   -- the 14.5 GiB dual bloom filter (1,504,982,117 addresses)
- `www/index.html`         -- the reseed39 bundle (add more files here freely; the dir is served)
- `pfbench`                -- the page-fault microbenchmark (ops only; not part of the service)

The server serves **every file** under `www/` (mime by extension; `/` -> `index.html`;
`..` rejected), so drop in extra assets as needed.

## 1. Run the server as a service
```
sudo cp deploy/reseed39-bloom.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now reseed39-bloom
systemctl status reseed39-bloom          # expect: "allow 127.0.0.1", loaded N addresses
curl -s localhost:8080/bloom-info        # {"service":"reseed39-bloom","version":1,...}
```
It binds `127.0.0.1` (via `BIND=` in the unit) so it is never directly reachable from
outside even if the firewall is wrong. Restarts on crash.

## 2. TLS certificate (Let's Encrypt)
Point the domain's A/AAAA record at oniric (DNS via Dreamhost), then:
```
sudo apt install certbot
sudo certbot certonly --standalone -d YOURDOMAIN     # needs :80 briefly; open it, then close
```
Certs land in `/etc/letsencrypt/live/YOURDOMAIN/`.

## 3. stunnel
```
sudo apt install stunnel4
sudo cp deploy/stunnel-reseed39.conf.example /etc/stunnel/reseed39.conf
sudoedit /etc/stunnel/reseed39.conf       # set YOURDOMAIN; pick accept = 443 or 4430 (below)
sudo systemctl enable --now stunnel4
```

### Getting :443 to stunnel -- pick ONE
**A. stunnel binds 443 directly (simplest, still unprivileged worker).** Set `accept = 443`
in the conf, grant the bind capability, and open 443:
```
sudo systemctl edit stunnel4     # add:
  [Service]
  AmbientCapabilities=CAP_NET_BIND_SERVICE
sudo ufw allow 443/tcp
```

**B. ufw DNAT 443 -> 4430 (what you sketched).** Keep `accept = 4430`. Add a nat rule at the
top of `/etc/ufw/before.rules` (above the `*filter` block):
```
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 4430
COMMIT
```
then:
```
sudo ufw allow 443/tcp
sudo ufw allow 4430/tcp        # REDIRECT rewrites the dport to 4430 *before* the filter chain,
                               # so ufw must permit 4430 for the redirected packets to pass
sudo ufw reload
```
Caveat: because the redirect happens before filtering, 4430 is then also reachable *directly*
from outside (harmless -- it's the same TLS listener -- but if that bothers you, prefer A).

Either way, **do not open 8080** -- it stays localhost-only.

## 4. Certificate renewal (don't skip -- LE certs are 90 days)
stunnel reloads its cert on SIGHUP. Wire it to certbot:
```
echo 'systemctl reload stunnel4' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-stunnel.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-stunnel.sh
```

## 5. Verify end to end
```
curl -s https://YOURDOMAIN/bloom-info                       # capability JSON over TLS
curl -s https://YOURDOMAIN/ -o /dev/null -w '%{http_code} %{size_download}\n'   # 200, ~1.1 MB
```
Then open `https://YOURDOMAIN/` in a browser, leave the Address field blank, and run a
known 2-blank-word recovery.

## Performance note (measured on oniric, 3.8 GiB RAM, slow VirtIO disk)
The filter (6.5 GiB filter1 hot set) does not fit in RAM here, so queries are disk-bound:
~1 major fault/query at ~830 us each => a single connection is served at ~1,000 programs/s
(~250 candidates/s for a 4-purpose search). It scales well across concurrent users
(~4,900 programs/s at 4 clients -- disk queue, not CPU). For single-user speed near the
client's ~2,100/s potential, the filter must be RAM-resident: an >=8 GiB box caches filter1
fully and the server becomes client-bound again. See BLOOM_PLAN.md.

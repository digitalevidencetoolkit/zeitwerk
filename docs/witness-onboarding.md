# Running a zeitwerk witness — partner onboarding

This page should contain everything you need to stand up a witness: 
- a small Python service, 
- a signing key, 
- and a git repository of published hours. 

A witness accepts document hashes, batches them into one Merkle tree per hour, signs the hourly root with its Ed25519 key, and publishes the leaf set + signature to public git remotes.

Note: A witness holds **no user data**.

## What you need

- A Linux box (Debian 12 / Ubuntu 22.04 or newer). A small VM is plenty: the service is a stdlib HTTP server with SQLite — 1 vCPU / 512 MB is fine.
- Python ≥ 3.11, `git`, `make`, outbound SSH (port 22) to your git forge. Debian and Ubuntu ship `venv` separately, and minimal cloud images lack some of the rest; `xxd` and `curl` are for the checks in step 6:

  ```sh
  sudo apt-get update && sudo apt-get install -y git make python3-venv curl xxd
  ```

- A git repository your witness can push to (Codeberg, GitHub, your institutional GitLab — anywhere public).
- No inbound ports beyond what you choose to expose (see TLS below).

If your policy mandates containers, use [`deploy/Dockerfile`](../deploy/Dockerfile) instead of steps 2–4; everything else is the same.

No box yet? [Appendix: a box on AWS, reachable over Tailscale](#appendix-a-box-on-aws-reachable-over-tailscale) is how the project's own witness was stood up.

## Setup

### 1. User and directories

```sh
sudo useradd --system --create-home --home-dir /var/lib/zeitwerk --shell /usr/sbin/nologin zeitwerk
sudo git clone --recurse-submodules https://github.com/digitalevidencetoolkit/zeitwerk /opt/zeitwerk
```

### 2. Build the environment

```sh
cd /opt/zeitwerk
sudo make setup       # creates .venv, installs dependencies; idempotent
sudo make test        # optional but recommended: the full suite, ~seconds
```

### 3. Git deploy key

The witness pushes every hour over SSH, non-interactively (`BatchMode=yes` is forced in code). We must then give the `zeitwerk` user its own deploy key:

```sh
sudo install -d -m 700 -o zeitwerk -g zeitwerk /var/lib/zeitwerk/.ssh
sudo -u zeitwerk ssh-keygen -t ed25519 -N "" -C "zeitwerk-witness@$(hostname)" -f /var/lib/zeitwerk/.ssh/id_ed25519
sudo -u zeitwerk cat /var/lib/zeitwerk/.ssh/id_ed25519.pub
```

Add the public key as a **write-access deploy key** on your epochs repository. 
- On Codeberg: the repository's *Settings → Deploy keys → Add deploy key*, and tick *Enable write access* 
- On GitHub: *Settings → Deploy keys*, and tick *Allow write access*.

Then accept the forge's host key once. Check the fingerprint first against the one your forge publishes ([Codeberg's](https://docs.codeberg.org/security/ssh-fingerprint/), [GitHub's](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)):

```sh
ssh-keyscan -t ed25519 codeberg.org 2>/dev/null | ssh-keygen -lf -
sudo -u zeitwerk ssh -o StrictHostKeyChecking=accept-new -T git@codeberg.org || true
```

Before the deploy key is added this prints `Permission denied (publickey)`; that is fine, the host key is recorded either way...

### 4. First run: create the signing key and set remotes

Remotes persist in the repo's git config. A remote added later still gets the full history on its first push, so you can also start without one and add it with this same command later on.

```sh
sudo -u zeitwerk /opt/zeitwerk/.venv/bin/python -m zeitwerk.server \
    --data-dir /var/lib/zeitwerk \
    --remote codeberg=git@codeberg.org:YOUR-ORG/zeitwerk-epochs.git
# watch it start, then Ctrl-C
```

The first start generates `signer.pem` — the witness's own Ed25519 private key.

> Note: **Back up `/var/lib/zeitwerk/signer.pem` now**, offline. Everything else (database, published repo) is reconstructible; the key is not. Losing it changes your `key_id`, which means re-registering with the federation. Treat it like a TLS private key: mode 0600, owner `zeitwerk`, one encrypted offline copy.

### 5. Install the service

```sh
sudo cp /opt/zeitwerk/deploy/zeitwerk-witness.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zeitwerk-witness
journalctl -u zeitwerk-witness -f    # watch the first hour close
```

### 6. Check it works

```sh
# the public key answers
curl -s http://127.0.0.1:14788/key | xxd | head -2

# submit a test digest, get a pending receipt
head -c 32 /dev/urandom > /tmp/digest
curl -s --data-binary @/tmp/digest http://127.0.0.1:14788/digest -o /tmp/receipt.ots

# after the top of the hour: the upgraded receipt, verified offline
curl -s http://127.0.0.1:14788/timestamp/$(xxd -p -c64 /tmp/digest) -o /tmp/upgraded.ots
curl -s http://127.0.0.1:14788/key -o /tmp/witness.pub
/opt/zeitwerk/.venv/bin/zeitwerk verify --receipt /tmp/upgraded.ots --key /tmp/witness.pub \
    $(xxd -p -c64 /tmp/digest)
```

You probably want to manually confirm the hour appeared in your public repo under `epochs/YYYY/MM/DD/HH/`.

## TLS and exposure

The service binds `127.0.0.1` and speaks plain HTTP – it's recommended you put your usual reverse proxy in front. With Caddy it is two lines:

```
witness.example.org {
    reverse_proxy 127.0.0.1:14788
}
```

Before anyone else can submit, cap each hour with `--max-leaves`. Everything an hour takes is pushed to your public repositories for good, and the tree allows a million fingerprints an hour: about 100 MB of history, in one hour, from one script. `--max-leaves 5000` keeps a full hour under half a megabyte; once it is full, the witness answers 503 until the next hour. Pick a number above the biggest batch you expect.

Once it is reachable, tell the witness its own address with `--recover-uri https://witness.example.org`. Every pending receipt includes that URI as the place to come back to for the upgrade.

Set both in an override rather than in the unit file, so they are yours whatever the template becomes. `sudo systemctl edit zeitwerk-witness` opens it; empty `ExecStart` first, then the whole command:

```ini
[Service]
ExecStart=
ExecStart=/opt/zeitwerk/.venv/bin/python -m zeitwerk.server \
    --data-dir /var/lib/zeitwerk --host 127.0.0.1 --port 14788 \
    --max-leaves 5000 --recover-uri https://witness.example.org
```

Then `sudo systemctl restart zeitwerk-witness`, and `systemctl cat zeitwerk-witness` shows the override after the unit.

Nothing the witness serves is secret. We use TLS for integrity and convention, but it does not deliver confidentiality.

## Operations and maintenance

- **Restarts:** All state is in `/var/lib/zeitwerk`; the service reseals and republishes any missed hours on startup.
- **Backup**: `signer.pem` (critical, once), `/var/lib/zeitwerk` (nice to have — the published git remotes already are the public record).
- **Updates**: `cd /opt/zeitwerk && sudo git pull --recurse-submodules && sudo make setup && sudo systemctl restart zeitwerk-witness`.
- **Monitoring**: `curl /key` is a liveness check; a commit on the epochs repo at most an hour after a submission is the real health signal. The status page at `/` shows both, and `curl -s /status.json` reads `"caught_up": true` once every finished hour is sealed, published and pushed to every remote. It reads false for up to a minute after each hour, until the closer gets to it.
- **Updates**: `sudo sh /opt/zeitwerk/deploy/update.sh` brings the witness to the latest `main`. It lists the commits it adds and takes away, installs them, restarts the service, then checks the witness answers with the same public key; one that came back with another key isn't using its signing key, and is stopped. Name a tag or commit to deploy that instead (going back included: it prints the command), or add `--dry-run` to only look. From a laptop with a clone of this repository, `make deploy WITNESS=you@your-witness` (or `make deploy-check`) runs the same script over ssh, even on a witness that predates it.
- **Moving to another machine**: a witness *is* its data directory (`signer.pem`, `zeitwerk.db`, `repo/` with its remotes in `.git/config`). Stop the old one, copy the directory over (compare `sha256sum signer.pem zeitwerk.db` and `git rev-parse HEAD` at both ends), give the new box the deploy key on every remote, start it. Then make sure the old copy can never start again, e.g. by renaming it. Two live copies of one key would sign different roots for the same hour, which to a verifier looks exactly like a stolen key.

## Publishing your key in DNS

Verifiers take your public key from your epochs repository, which anyone who copies the repository can swap for their own. Publish it in a DNS zone you control as well, and `zeitwerk verify --dns <your domain>` checks the signer of an hour against it. From any clone of your repository:

```sh
zeitwerk dns-record signers/<key_id>.pub
# v=zw0; k=ed25519; p=<your key, base64>
```

Add that value as a TXT record at `_zeitwerk.<your domain>`, with DNSSEC on the zone if your registrar offers it. `--dns` reads every TXT value at that name, so several witnesses can share one. Check it with `dig +short TXT _zeitwerk.<your domain>`, then with `zeitwerk verify <a fingerprint> --epochs <your clone> --dns <your domain>`, whose `dns` line should say `confirmed`.

## Registering with the federation

Email <hi@digitalevidencetoolkit.org> with:

1. Your public key: the output of `curl -s http://127.0.0.1:14788/key | xxd -p` (also published as `signers/<key_id>.pub` in your epochs repo).
2. The URL of your epochs repository.
3. Your public endpoint (if you expose one) and an operational contact.
4. The domain that publishes your key (see above).

We add your witness to [`federation.json`](../federation.json): key id, operator, records, status page, and the domain that publishes your key. Adding a witness is one pull request, so you can also open it yourself. Nothing counts signatures toward an N-of-M threshold yet: each witness's hours verify on their own, and checking that witnesses agree is the next piece. Key rotation and signer exit have no written rules yet (#36).

## Appendix: a box on AWS, reachable over Tailscale

How the project's own witness was stood up: the cheapest EC2 machine that meets the 512 MB floor, with **no inbound ports open to the internet**. You reach it over your tailnet; it only ever dials out (to Tailscale, apt, PyPI and the git forge). About $7–8/month: ~$3 instance, $3.65 public IPv4, <$1 disk. The public IPv4 cannot be dropped to save money: GitHub, which the clone in step 1 pulls from, has no IPv6.

### A0. An AWS identity for this, not an app key

Use a dedicated IAM user (here `zeitwerk-deploy`) with its own CLI profile, not the key of some application. EC2 rights on an app key widen what a leak of that key can do. This policy is enough to create and tear down the box:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "ec2:RunInstances", "ec2:CreateTags",
      "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress", "ec2:ImportKeyPair",
      "ec2:TerminateInstances", "ec2:DeleteSecurityGroup", "ec2:DeleteKeyPair"
    ],
    "Resource": "*"
  }]
}
```

Set profile and region as environment variables, not as a `$OPTS` string (zsh does not word-split it, and every call fails on argument parsing):

```sh
export AWS_PROFILE=zeitwerk-deploy AWS_REGION=eu-north-1   # Stockholm: cheapest EU region bar Dublin
```

### A1. Key pair, security group, instance

`t4g.nano` (Graviton, 2 burst vCPU, 512 MB) running the official Debian 12 arm64 image (Debian's AWS account is `136693071363`). The security group starts with one temporary rule, SSH from your current IP only, to bootstrap Tailscale; A3 removes it.

```sh
VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
AMI=$(aws ec2 describe-images --owners 136693071363 \
    --filters 'Name=name,Values=debian-12-arm64-*' Name=state,Values=available \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
MYIP=$(curl -s https://checkip.amazonaws.com)

aws ec2 import-key-pair --key-name zeitwerk-witness --public-key-material fileb://$HOME/.ssh/id_ed25519.pub
SG=$(aws ec2 create-security-group --group-name zeitwerk-witness \
    --description "zeitwerk witness: no inbound, tailnet only" --vpc-id $VPC --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $SG \
    --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MYIP/32,Description=bootstrap}]"

aws ec2 run-instances --image-id $AMI --instance-type t4g.nano \
    --key-name zeitwerk-witness --security-group-ids $SG \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=8,VolumeType=gp3,Encrypted=true}' \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=zeitwerk-witness}]' \
    --query 'Instances[0].InstanceId' --output text
```

The login user on Debian images is `admin`: `ssh admin@<public-ip>` (from `aws ec2 describe-instances`).

### A2. Join the tailnet

```sh
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg \
    | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list \
    | sudo tee /etc/apt/sources.list.d/tailscale.list >/dev/null
sudo apt-get update && sudo apt-get install -y tailscale
sudo tailscale up --hostname=zeitwerk-witness     # prints a login URL: open it, approve the machine
```

In the Tailscale admin console, **disable key expiry** for this machine; otherwise it drops off the tailnet after 180 days and you are locked out.

### A3. Close the door

From a machine on the same tailnet, check that you get in over Tailscale, *then* remove the bootstrap rule:

The host key over the tailnet must be the one you accepted over the public IP (compare `ssh-keyscan -t ed25519 zeitwerk-witness | ssh-keygen -lf -`).

```sh
ssh admin@zeitwerk-witness hostname        # MagicDNS name; must work before the next line
aws ec2 revoke-security-group-ingress --group-id $SG \
    --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MYIP/32}]"
```

The security group now has no inbound rules at all, and Tailscale still works: everything goes through connections the box dials out. Whether they are *direct* depends on your side. If `tailscale ping zeitwerk-witness` says `via DERP(...)`, your NAT changes the port for each destination (`tailscale netcheck` shows `MappingVariesByDestIP: true`) and the traffic goes through a Tailscale relay: fine for SSH, ~100–200 ms. To get a direct connection, allow WireGuard in. It is an inbound port, but it only answers tailnet peers:

```sh
aws ec2 authorize-security-group-ingress --group-id $SG \
    --ip-permissions "IpProtocol=udp,FromPort=41641,ToPort=41641,IpRanges=[{CidrIp=0.0.0.0/0,Description=tailscale-wireguard}]"
```

Continue with [Setup](#setup) over `ssh admin@zeitwerk-witness`.

### A4. Open it to the public, for a while

Tailscale Funnel serves the witness at `https://<machine>.<tailnet>.ts.net` without opening an inbound port: the box still only dials out. Turn on HTTPS certificates and Funnel for the machine in the admin console first, set `--max-leaves` and `--recover-uri https://<machine>.<tailnet>.ts.net` (see [TLS and exposure](#tls-and-exposure)), then:

```sh
sudo tailscale funnel --bg 14788    # public from now on
tailscale funnel status
sudo tailscale funnel reset         # private again
```

The ts.net address ends up in every pending receipt issued meanwhile and stops answering once Funnel is off. Those receipts still upgrade: each names its hour, so `zeitwerk verify` rebuilds it from the published repository. For a permanent endpoint, use your own domain (A5).

### A5. Your own domain, with Caddy

How the project's witness became `witness.digitalevidencetoolkit.org`: a fixed address, a DNS name, and Caddy for HTTPS. Ports 80 and 443 are then open to everyone; SSH stays on the tailnet.

A fixed address first. The automatic public IP changes whenever the instance is stopped and started; an Elastic IP doesn't, and costs the same while attached, since it replaces the automatic one. It needs `ec2:AllocateAddress` and `ec2:AssociateAddress`, which A0's policy leaves out: add them, or do this step in the console.

```sh
EIP=$(aws ec2 allocate-address --domain vpc --query AllocationId --output text)
aws ec2 associate-address --instance-id <instance-id> --allocation-id $EIP
aws ec2 describe-addresses --allocation-ids $EIP --query 'Addresses[0].PublicIp' --output text
```

Point an `A` record for `witness.example.org` at that address. Then install Caddy from its own repository (bookworm's is 2.6), and make `/etc/caddy/Caddyfile` the two lines from [TLS and exposure](#tls-and-exposure). Leave out any `log` directive: Caddy then keeps no access log, so it collects no client IPs, like the witness.

```sh
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update && sudo apt-get install -y caddy
```

Set `--max-leaves` and `--recover-uri https://witness.example.org` in the override, then open the door, last. Port 80 answers Let's Encrypt and redirects to HTTPS.

```sh
aws ec2 authorize-security-group-ingress --group-id $SG --ip-permissions \
    'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0,Description=caddy}]' \
    'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description=caddy}]'
sudo systemctl restart caddy    # fetches its certificate, then serves
curl -s https://witness.example.org/key | xxd -p    # the same key as on the box
```

Closing it again is `revoke-security-group-ingress` with the same rules and `sudo systemctl disable --now caddy`. Receipts issued meanwhile keep their URL, and still upgrade from the published repository.

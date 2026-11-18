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

Once it is reachable, tell the witness its own address with `--recover-uri https://witness.example.org` in the unit's `ExecStart`. Every pending receipt includes that URI as the place to come back to for the upgrade.

Nothing the witness serves is secret. We use TLS for integrity and convention, but it does not deliver confidentiality.

## Operations and maintenance

- **Restarts:** All state is in `/var/lib/zeitwerk`; the service reseals and republishes any missed hours on startup.
- **Backup**: `signer.pem` (critical, once), `/var/lib/zeitwerk` (nice to have — the published git remotes already are the public record).
- **Updates**: `cd /opt/zeitwerk && sudo git pull --recurse-submodules && sudo make setup && sudo systemctl restart zeitwerk-witness`.
- **Monitoring**: `curl /key` is a liveness check; a commit on the epochs repo at most an hour after a submission is the real health signal.
- **Moving to another machine**: a witness *is* its data directory (`signer.pem`, `zeitwerk.db`, `repo/` with its remotes in `.git/config`). Stop the old one, copy the directory over (compare `sha256sum signer.pem zeitwerk.db` and `git rev-parse HEAD` at both ends), give the new box the deploy key on every remote, start it. Then make sure the old copy can never start again, e.g. by renaming it. Two live copies of one key would sign different roots for the same hour, which to a verifier looks exactly like a stolen key.

## Registering with the federation

Email <hi@digitalevidencetoolkit.org> with:

1. Your public key: the output of `curl -s http://127.0.0.1:14788/key | xxd -p` (also published as `signers/<key_id>.pub` in your epochs repo).
2. The URL of your epochs repository.
3. Your public endpoint (if you expose one) and an operational contact.

We add your key and repo to the federation list; verifiers then count your signature toward the N-of-M threshold. The governance detail (key rotation, signer exit) is in the federation design note.

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

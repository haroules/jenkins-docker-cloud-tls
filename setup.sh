#!/bin/bash
# output variables, and other debug info
debug=1 
# set the execute flag to 1 to prevent accidental execution
# user must set a flag on the cli to actually execute 
execute=1
# set skip checks to 1 (default will run them) 
skipchecks=1
# set to 0 to ignore git finding untracked files
ignoregit=1
# password for jenkins user supplied if -p selected
jenkspassword="default"
# jenkins keystore pw user supplied if -k selected
jenkskeystorepw="changeit"
# jenkins cacerts pw user supplied if -c selected
jenkscacertpw="changeit"

parse_cli () {
    local OPTIND
    optionselected=""
    while getopts "c:deghk:p:s" opt; do
        case $opt in
            c | -c | --c)
                echo "Option -c selected, password for Jenkins cacerts supplied!"
                jenkscacertpw=$OPTARG
                optionselected+="-c "
                ;;    
            d | -d | --d)
                echo "Option -d selected, will be more verbose!"
                debug=0
                optionselected+="-d "
                ;;
            e | -e | --e)
                echo "Option -e selected, will execute rather than dry-run!"
                execute=0
                optionselected+="-e "
                ;;
            g | -g | --g)
                echo "Option -g selected, will ignore if git finds untracked changes"
                ignoregit=0
                optionselected+="-g "
                ;;
            k | -k | --k)
                echo "Option -k selected, password for Jenkins keystore supplied!"
                jenkskeystorepw=$OPTARG
                optionselected+="-k "
                ;;
            p | -p | --p)
                echo "Option -p selected, password for Jenkins application supplied!"
                jenkspassword=$OPTARG
                optionselected+="-p "
                ;;
            s | -s | --s)
                echo "Option -s selected, skipping pre-requisite checks!"
                skipchecks=0
                optionselected+="-s "
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
        echo "No options selected, or malformed input provided, running non execute mode with defaults."
        execute=1
        skipchecks=1
    else
        if [ $debug -eq 0 ]; then
            echo "Options selected: $optionselected"
        fi
    fi
}

printhelp () {
     echo "./setup.sh -e -d -g -s -c [password for cacerts] -k [password for java keystore] -p [password for jenkins]"
     echo "-e would execute and actually run the script, default is dry-run print what it would do."
     echo "-d would turn on debug mode and print more output"
     echo "-g would turn on debug mode and print more output"
     echo "-s would skip pre-requisite checks."
     echo "-c is to supply the password for the cacerts store used by jenkins."
     echo "-p is to supply the password for the jenkins user."
     echo "-k is to supply the password for the java keystore used by jenkins."
     echo "default password stored in script used when -p, -k, or -c is not specified."
     exit 0
}

check_binary_available () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: check_binary_available--"; fi
    binarylist=(git docker openssl keytool wget java curl jq yq sed)
    for i in "${binarylist[@]}"; do
        # Check if the binary exists
        if command -v "$i" >/dev/null 2>&1; then
            if [ $debug -eq 0 ]; then echo "$i is installed."; fi
        else
            echo "$i is not installed, exiting."
            exit -1
        fi    
    done
    echo "Required binaries appear to be installed"
}

check_docker_rootless() {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: check_docker_rootless--"; fi
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
    if [ $debug -eq 0 ]; then echo -e "\n--Function: check_docker_api--"; fi
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
        if [ $debug -eq 0 ]; then echo "Docker access via API appears functional."; fi
    fi
    #verify context is rootless from API
    if [[ $DockerInfoOutput == *"Context:    rootless"* ]]; then
        if [ $debug -eq 0 ]; then echo "API response indicates rootless mode in use."; fi
    else
        echo "API response doesn't indicate rootless context in use, exiting."
        exit -1
    fi
    #verify connection to running host matches hostname
    if [[ $DockerInfoOutput == *"Name: $hostname"* ]]; then
        if [ $debug -eq 0 ]; then echo "API response indicates connection to $hostname is good."; fi
    else
        echo "API response indicates connection to $hostname is bad, exiting."
        exit -1
    fi
    echo "Docker access via API appears functional."
}

clean_intermediate_files () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: clean_intermediate_files--"; fi
    #use git to confirm the workspace is clean, ignore if flag set so you can test changes
    gitstatus=$(git status -s | wc -l)
    if (( "$gitstatus" > 0 )); then
        if [ $ignoregit -eq 0 ]; then   
            git status -s
            echo "git indicates sandbox has modified files, but ignore was chosen!"
        else
            git status -s
            echo "git indicates sandbox has modified files, use -g or git reset --hard for next run.  exiting!"
            exit -1
        fi
    fi
    # list of files to be cleaned for each run. 
    filelist=(cacerts docker_api_root_ca.pem ca-cert.srl ca-key.pem server-req.pem server-key.pem server-ext.cnf server-cert.pem jenkins_keystore.jks jenkins.p12 jenkins-cli.jar)
    if [[ $execute == 0 ]]; then
        for i in "${filelist[@]}"; do
            if [ -f $i ]; then
                rm -v $i
            fi    
        done
    else
        echo "Would have run the following cleanup if execute flag was set:"
        for i in "${filelist[@]}"; do
            if [ -f $i ]; then
                 echo "rm -v $i"
            fi    
        done
    fi
}

clean_docker_resources () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: clean_docker_resources--"; fi
    #make sure container, volumes don't exist already (take stack down, worst case doesn't exist yet, otherwise old gets cleaned up on the fly)
    #todo handle errors on docker compose down
    if [ $debug -eq 0 ]; then
        CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml down -v
    else
        CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml down -v > /dev/null 2>&1
    fi
    
    if [ $debug -eq 0 ]; then echo "Removing dangling images if they exist."; fi
    danglecount=`docker image ls --filter "dangling=true" | wc -l`
    if (( "$danglecount" > 1 )); then
        dangleout=$(docker image ls --filter "dangling=true")
        if [ $debug -eq 0 ]; then echo -e "dangling images found: \n$dangleout"; fi
        if [[ $execute -eq 0 ]]; then
            docker image prune --filter "dangling=true" -f
        else
            echo "Dangline images would have been pruned, if execute flag set"
        fi
    fi

    if [ $debug -eq 0 ]; then echo "Remove unused volumes if they exist."; fi
    # docker volume ls always has top line of output so any lines after indicate volume names
    volumecount=`docker volume ls | wc -l`
    if (( "$volumecount" > 1 )); then
        volumesoutput=$(docker volume ls --format \{\{.Name\}\})
        if [ $debug -eq 0 ]; then echo -e "volumes found: \n$volumesoutput"; fi
        if [[ $execute -eq 0 ]]; then
            volumedangle=$(docker volume ls -q -f dangling=true)
            docker volume rm $volumedangle
        else
            echo "Unused volumes would have been removed, if execute flag set"
        fi
    else
        if [ $debug -eq 0 ]; then echo "No unused volumes detected"; fi
    fi
}

check_certificate () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: check_certificate--"; fi
    inputcert=$1
    # check valid for at least 2 weeks
    certcheckoutput=$(openssl x509 -in $inputcert -text -noout -checkend "1209600")
    if [[ $certcheckoutput == *"Certificate will not expire"* ]]; then
        if [ $debug -eq 0 ]; then echo "$inputcert is good for at least 2 weeks."; fi
    else
        echo "$inputcert will expire in less than 2 weeks, exiting."
        exit -1
    fi
    # opinionated check certificate CommonName matches hostname
    if [[ $certcheckoutput == *"CN = $hostname"* ]]; then
        if [ $debug -eq 0 ]; then echo "$inputcert CN matches hostname."; fi
    else
        echo "$inputcert CN doesn't match hostname, exiting."
        exit -1
    fi
    echo -e "certificate $1 appears valid"
}

pull_latest_image () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: pull_latest_image--"; fi
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

    if [ $debug -eq 0 ]; then echo "Checking for available update for $IMAGE_REGISTRY/$IMAGE_PATH:$IMAGE_TAG..."; fi
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
    if [ $debug -eq 0 ]; then echo "Remote digest: ${DIGEST_REMOTE}"; fi
    # compare digests and do a pull if they don't match
    if [ "$DIGEST_LOCAL" != "$DIGEST_REMOTE" ] ; then
        if [ $debug -eq 0 ]; then echo "Latest image $IMAGE_INPUT doesn't exist locally."; fi
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
        echo "$IMAGE_INPUT  Already up to date. Nothing to do."
    fi
}

generate_controller_cacerts () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: generate_controller_cacerts--"; fi
    if [[ $execute -eq 0 ]]; then
        if [ $debug -eq 0 ]; then echo "Get CA cert from local docker API and verify it"; fi
        #openssl s_client -showcerts -connect $hostname:2376 </dev/null 2>/dev/null | openssl x509 -outform PEM > docker_api_root_ca.pem
        showcert=$(openssl s_client -showcerts -connect $hostname:2376 </dev/null 2>/dev/null) 
        # output should be the cert, if no output something went wrong
        if [ -z "${showcert}" ]; then
            echo "openssl couldn't connect to docker endpoint, exiting. is docker api running or network down ?"
            exit -1
        fi
        echo "$showcert" | openssl x509 -outform PEM > docker_api_root_ca.pem
        # check file exists and isn't empty
        if [[ ! -f docker_api_root_ca.pem  || ! -s docker_api_root_ca.pem ]] then
            echo "docker_api_root_ca.pem wasn't generated, exiting."
            exit -1
        fi
        # do some basic cert check for hostname and validity
        check_certificate docker_api_root_ca.pem
       
        # programatically get cacerts file from existing jenkins controller container
        # delete exploded filesystem when done
        echo 'FROM jenkins/jenkins:lts-jdk17' > DockerfileGetcacerts
        if [ $debug -eq 0 ]; then 
            docker build -f DockerfileGetcacerts -o jenkinsrootfs .
        else
            docker build -f DockerfileGetcacerts -o jenkinsrootfs . > /dev/null 2>&1
        fi
        cp -v jenkinsrootfs/opt/java/openjdk/lib/security/cacerts cacerts
        rm -rf jenkinsrootfs

        #import ca cert pem into cacerts keystore from controller container (allows jenkins to talk to Docker API over tls)
        # can't change the default storepass as supplied by jenkins
        keytoolimportoutput=$(keytool -import -noprompt -trustcacerts -storepass changeit -file docker_api_root_ca.pem -alias $hostname -keystore cacerts)
        if [ "$?" -ne 0 ]; then
            echo "keytool import of ca cert pem into cacerts failed, exiting."
            echo "$keytoolimportoutput"
            exit -1
        else
            if [ $debug -eq 0 ]; then echo "keytool import of ca cert pem into cacerts appears successful."; fi
        fi
        controllercacertscheck=$(keytool -list -keystore cacerts -alias $hostname -storepass changeit)
        if [[ $controllercacertscheck =~ $hostname && $controllercacertscheck =~ "trustedCertEntry" ]] then
            if [ $debug -eq 0 ]; then echo "keytool lists Docker API CA alias in keystore cacerts as trusted entry."; fi
        else
            echo "keytool isnt showing Docker API  CA cert imported correctly"
            exit -1
        fi
        if [ $debug -eq 0 ]; then echo "Changing cacerts default password of changeit for security"; fi
        keytool -storepasswd -keystore cacerts -storepass changeit -new $jenkscacertpw
    else
        echo "Execute flag not set, here's what i would have done to generate controller cacerts:"
        echo -e "\t 1.) openssl s_client -showcerts -connect $hostname:2376 </dev/null 2>/dev/null | openssl x509 -outform PEM > docker_api_root_ca.pem"
        echo -e "\t 2.) echo 'FROM jenkins/jenkins:lts-jdk17' > DockerfileGetcacerts"
        echo -e "\t 3.) docker build -f DockerfileGetcacerts -o jenkinsrootfs ."
        echo -e "\t 4.) cp -v jenkinsrootfs/opt/java/openjdk/lib/security/cacerts cacerts"
        echo -e "\t 5.) rm -rf jenkinsrootfs"
        echo -e "\t 6.) keytool -import -noprompt -trustcacerts -storepass changeit -file docker_api_root_ca.pem -alias $hostname -keystore cacerts"
        echo -e "\t 7.) keytool -list -keystore cacerts -alias $hostname -storepass changeit"
        echo -e "\t 8.) keytool -storepasswd -keystore cacerts -storepass changeit -new [pw redacted]"
    fi
    echo "Generate cacerts for controller completed."
}

generate_jenkins_app_certs_and_keystore () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: generate_jenkins_app_certs_and_keystore--"; fi
    if [[ $execute -eq 0 ]]; then
        #generate certs for tls encryption of jenkins controller
        if [ $debug -eq 0 ]; then echo "generate CA"; fi
        openssl req -x509 -newkey rsa:4096 -days 360 -nodes -keyout ca-key.pem -out ca-cert.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-CA/emailAddress=" >/dev/null 2>&1
        if [ $debug -eq 0 ]; then echo "generate jenkins server priv key and csr"; fi
        openssl req -newkey rsa:4096 -keyout server-key.pem -nodes -out server-req.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-Server/emailAddress=" >/dev/null 2>&1
        if [ $debug -eq 0 ]; then echo "generate alt names file for cert"; fi
        echo "subjectAltName=DNS:$hostnameshort,DNS:$hostname,IP:$ip" > server-ext.cnf
        if [ $debug -eq 0 ]; then echo "generate jenkins server cert"; fi
        openssl x509 -req -in server-req.pem -days 360 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf >/dev/null 2>&1
        # check cert won't expire and CommonName incudes hostname
        check_certificate server-cert.pem
        #verify generated server cert against CA
        servercertcheck=$(openssl verify -CAfile ca-cert.pem server-cert.pem)
        if [[ $servercertcheck =~ "server-cert.pem: OK" ]] then
           if [ $debug -eq 0 ]; then echo "Generated CA and cert passed verification."; fi
        else
            echo "Generated CA and cert did not pass verification, exiting."
            exit -1
        fi
        if [ $debug -eq 0 ]; then echo "generate jenkins keystore to hold self signed cert"; fi
        keytool -genkey -dname "cn=jenkins, ou=$hostnameshort, o=$domainname, c=US" -keyalg RSA -alias jenkinselfsigned -keystore jenkins_keystore.jks -storepass $jenkskeystorepw -keysize 4096 -validity 365
        if [ $debug -eq 0 ]; then echo "create pkcs12 file of server cert and key"; fi
        openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem -out jenkins.p12 -password pass:$jenkskeystorepw
        if [ $debug -eq 0 ]; then echo "import pkcs12 file to keystore"; fi
        keytool -importkeystore -noprompt -srckeystore jenkins.p12 -srcstoretype PKCS12 -destkeystore jenkins_keystore.jks -deststoretype JKS -deststorepass $jenkskeystorepw -srcstorepass $jenkskeystorepw
        if [ $debug -eq 0 ]; then echo "import server ca to keystore"; fi
        keytool -importcert -noprompt -keystore jenkins_keystore.jks -trustcacerts -alias $hostname-JenkinsCA -file ca-cert.pem -deststorepass $jenkskeystorepw
        if [ $debug -eq 0 ]; then echo "update docker compose env file to reflect jenkins keystore pw"; fi
        sed -i -E "s/httpsKeyStorePassword=.*\"/httpsKeyStorePassword=$jenkskeystorepw\"/" jenkins-controller-docker-compose.env
    else
        echo "Execute flag not set, here's what i would have done to generate jenkins server CA, certs and keystore:"
        echo -e "\t 1.) openssl req -x509 -newkey rsa:4096 -days 360 -nodes -keyout ca-key.pem -out ca-cert.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-CA/emailAddress=" >/dev/null 2>&1"
        echo -e "\t 2.) openssl req -newkey rsa:4096 -keyout server-key.pem -nodes -out server-req.pem -subj "/C=US/ST=MA/L=Boston/O=Self/OU=jenkins/CN=$hostname-Server/emailAddress=" >/dev/null 2>&1"
        echo -e "\t 3.) echo "subjectAltName=DNS:$hostnameshort,DNS:$hostname,IP:$ip" > server-ext.cnf"
        echo -e "\t 4.) openssl x509 -req -in server-req.pem -days 360 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf >/dev/null 2>&1"
        echo -e "\t 5.) keytool -genkey -dname "cn=jenkins, ou=$hostnameshort, o=$domainname, c=US" -keyalg RSA -alias jenkinselfsigned -keystore jenkins_keystore.jks -storepass [pw redacted] -keysize 4096 -validity 365"
        echo -e "\t 6.) openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem -out jenkins.p12 -password pass:[pw redacted]"
        echo -e "\t 7.) keytool -importkeystore -noprompt -srckeystore jenkins.p12 -srcstoretype PKCS12 -destkeystore jenkins_keystore.jks -deststoretype JKS -deststorepass [pw redacted] -srcstorepass [pw redacted]"
        echo -e "\t 8.) keytool -importcert -noprompt -keystore jenkins_keystore.jks -trustcacerts -alias $hostname-JenkinsCA -file ca-cert.pem -deststorepass [pw redacted]"
    fi
    echo "Generation of jenkins server CA, certs, and kestore completed."
}

update_jenkins_casc () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: update_jenkins_casc--"; fi
    # todo: update URL and other items that rely on hostname
    # todo: programatically insert docker api credential from local files 
    # so that jenkins can talk to docker api
    if [ $debug -eq 0 ]; then echo "Update jenkins configuration as code (casc) yaml file from data collected in this script"; fi
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
    if [[ "$jenkspassword" != "default" ]]; then
        echo "User supplied password will be injected"
        yq -i ".jenkins.securityRealm.local.users[0].password=\"$jenkspassword\"" casc.yaml
    fi
    echo "Autofill of jenkins casc credentials and configuration successful."
}

build_container_and_run_stack () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: build_container_and_run_stack--"; fi
    # build container and stand up application
    # todo: stack name from date/time rather than static name
    if [[ $execute -eq 0 ]]; then
        if [ $debug -eq 0 ]; then echo "Running docker compose and standing up app stack"; fi
        CONTAINER_NAME=jenkins-controller-1 JENKINS_HOME=jenkins-home-1 docker compose -f jenkins-controller-docker-compose.yaml up --build -d
        if [ $debug -eq 0 ]; then echo "Verify container running post compose"; fi
        container_running_check="docker container inspect -f '{{.State.Status}}' jenkins-controller-1"
        container_running=1
        while [ $container_running -eq 1 ]
        do 
            container_check_output=$($container_running_check)
            if [[ "$container_check_output" =~ "running" ]]; then
                if [ $debug -eq 0 ]; then echo "container now running"; fi
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
        if [ $debug -eq 0 ]; then echo "Check jenkins app responding via curl"; fi
        app_running_check="curl -Isk https://$hostname:8443/jnlpJars/jenkins-cli.jar | head -1"
        app_running=1
        while [ $app_running -eq 1 ]
        do 
            app_check_output=$($app_running_check)
            if [[ "$app_check_output" =~ "HTTP/1.1 200 OK" ]]; then
                if [ $debug -eq 0 ]; then echo "jenkins app now running"; fi
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
    echo -e "\nJenkins controller container built and compose successful."
}

exercise_jenkins () {
    if [ $debug -eq 0 ]; then echo -e "\n--Function: exercise_jenkins--"; fi
    if [[ $execute -eq 0 ]]; then
        if [ $debug -eq 0 ]; then echo "retrieving latest jenkins cli jar from app"; fi
        wget -q https://$hostname:8443/jnlpJars/jenkins-cli.jar --no-check-certificate
        if [ ! -f jenkins-cli.jar ]; then
            echo "Unable to retrieve jenkins-cli.jar, exiting."
            exit -1
        fi
        if [ $debug -eq 0 ]; then echo "uploading a container agent test job"; fi
        jobupload=$(java -Djavax.net.ssl.trustStore=jenkins_keystore.jks -Djavax.net.ssl.trustStorePassword=$jenkskeystorepw -jar jenkins-cli.jar -auth admin:$jenkspassword -s https://$hostname:8443/ create-job "Test Agent" < TestAgent.xml )
        if [ "$?" -ne 0 ]; then
            echo "Job upload failed, exiting."
            echo "$jobupload"
            exit -1
        fi
    else
        echo "Execute flag not set, here's what i would have done:"
        echo "wget -q https://$hostname:8443/jnlpJars/jenkins-cli.jar --no-check-certificate"
        echo "java -Djavax.net.ssl.trustStore=jenkins_keystore.jks -Djavax.net.ssl.trustStorePassword=[*pw redact*] -jar jenkins-cli.jar -auth admin:[*pw redact*] -s https://$hostname:8443/ create-job "Test Agent" < TestAgent.xml"
    fi
    echo "Retrieval of jenkins cli jar and upload of sample job successful."
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
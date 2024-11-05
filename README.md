docker run --userns host --privileged --name falco-eventgen -it --rm falcosecurity/event-generator run syscall
docker run --userns host --privileged --name falco-eventgen -it --rm falcosecurity/event-generator --entrypoint /bin/sh 
docker run --userns host --privileged --name falco-eventgen -it --rm --entrypoint /bin/sh  falcosecurity/event-generator
docker run --userns host --privileged --name falco-eventgen -it --rm --entrypoint /bin/sh software-testing/tester

sudo ./falco_binary -c ./falco.yaml -r ./falco_rules.yaml
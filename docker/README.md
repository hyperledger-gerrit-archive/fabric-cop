# To build a docker image with cop
docker build fabric-cop -t fabric-cop:latest

# To execute the cop server and cop clients
docker-compose -f docker-compose-cop.yml up --force-recreate -d


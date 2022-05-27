sudo docker build . -t fossephate/nautilus-backend
sudo docker push fossephate/nautilus-backend:latest

kubectl replace -f ./kubernetes/nautilus/deployment.yaml

# DNS:
doctl compute domain records create perish.co --record-type "A" --record-name "nautilus" --record-data "45.55.125.226" --record-ttl "30"

doctl compute domain records list perish.co
doctl compute domain records create perish.co --record-type "A" --record-name "backend" --record-data "45.55.125.226" --record-ttl "30"


doctl compute domain records create perish.co --record-type "CNAME" --record-name "test-app" --record-data "custom.bnc.lt" --record-ttl "30"
doctl compute domain records create perish.co --record-type "CNAME" --record-name "app" --record-data "custom.bnc.lt" --record-ttl "30"
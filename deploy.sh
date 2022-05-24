sudo docker build . -t fossephate/nautilus-backend
sudo docker push fossephate/nautilus-backend:latest

doctl compute domain records create perish.co --record-type "A" --record-name "backend" --record-data "45.55.125.226" --record-ttl "30"
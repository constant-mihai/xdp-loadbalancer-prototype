# XDP Load Balancer Prototype

A playground for doing packet manipulation in XDP.

## Build

The Makefile has some targets to help build.

## To Run
```
docker compose up -d
```

To send traffic with trex:
```
docker compose exec -it trex /bin/bash
./t-rex-64 -f cap2/dns.yaml -c 1 -m 1 -d 10
```

## xlbp metrics
```
docker compose exec -it xlbp /bin/bash
curl http://172.20.15.10:9090
```

## TODO:

- Check again what happens with the trex_cfg.yaml. Docker compose will allocate the interfaces randomly. I don't remember if this matters for the trex config or not.

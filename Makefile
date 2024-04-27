build: node_modules
	docker run -it --rm -v ./:/mnt node:20 sh -c "cd /mnt && npm run build"
node_modules:
	docker run -it --rm -v ./:/mnt node:20 sh -c "cd /mnt && npm install"
start:
	docker compose up -d --build
logs: start
	docker compose logs -f
dev: stop start
	docker compose logs -f &
	docker compose watch --no-up
stop:
	docker compose down --remove-orphans
restart: stop start
clean: stop
	docker run -v ./:/mnt node:20 sh -c "cd /mnt && npm run clean"
	docker compose down -v
	docker image rm docker.notmike.net/registry -f
	docker image rm docker.ide.notmike.net/registry -f
	docker system prune -f
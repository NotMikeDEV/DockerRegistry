# Docker Registry
```javascript
const express = require("express")
const http = require("http")
const DockerRegistry = require("@notmike/dockerregistry").default

function AuthFunction(Resource, Username, Password) {
	if (Username == 'user' && Password == 'password')
		return true
	return false
}

console.log('Starting Server')
const port = 5001
const app = express()
const server = http.createServer(app)
const Registry = new DockerRegistry({Express: app, DataDir: '.', AuthFunction})
server.listen( port, '::', ()=>{
	console.log('Daemon', 'Listening on port', port)
} )
```
or (default unauthenticated server in docker)
```
docker compose up -d --build
```

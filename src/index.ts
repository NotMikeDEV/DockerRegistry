import express from "express"
import * as http from "http"
import DockerRegistry from "./Registry"
export default DockerRegistry

if (require.main === module && process.argv.length>2 && process.argv[2] == 'server') {
	console.log('Starting Server')
	const port = 5000
	const app = express()
	const server = http.createServer(app)
	app.use((req:any, res:any, next:Function)=>{
		console.log(req.ip, req.method, req.url)
		next()
	})
	const Registry = new DockerRegistry({Express: app})
	server.listen( port, '::', ()=>{
		console.log('Daemon', 'Listening on port', port)
	} )
}

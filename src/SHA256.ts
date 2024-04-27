import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads'
import crypto from 'crypto'

export default class SHA256Thread {
	_Hash:Promise<string>
	_Resolver:Function
	_Worker:Worker|undefined
	constructor() {
		this._Resolver = ()=>{}
		this._Hash = new Promise(R=>this._Resolver=R)
		this._Worker = new Worker(__filename)
	}
	Append(Data:Buffer|string) {
		this._Worker?.postMessage(['Data', Data])
	}
	async Sum() {
		if (this._Worker) {
			this._Worker.on('message', (Result)=>{
				this._Worker?.terminate()
				this._Worker = undefined
				this._Resolver(Result)
			})
			this._Worker.postMessage(['Sum'])
		}
		return await this._Hash
	}
}
if (require.main === module && !isMainThread) {
	const Hash = crypto.createHash('sha256')
	parentPort?.on('message', (Request) => {
		if (Request[0] == 'Data')
			Hash.update(Request[1])
		else if (Request[0] == 'Sum')
			parentPort?.postMessage(Hash.digest('hex'))
	})
}
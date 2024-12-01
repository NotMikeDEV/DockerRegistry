import fsP from 'fs/promises'
import fs from 'fs'
import crypto from 'crypto'
import Lock from './Lock'
import SHA256Thread from './SHA256'
import path from 'node:path'

type AuthFunction = (Resource:string[], Username:string, Password:string) => Promise<boolean>

interface Options {
	Express:any
	DataDir?:string,
	Debug?:boolean,
	AuthFunction?:AuthFunction
}
interface ReapObject {
	ReapAt:Date,
	File:string
}
export default class DockerRegistry {
	Options:Options
	Uploads:any={}
	Debug:Function=(...args:any[])=>console.log(...args)
	ReapQueue:ReapObject[]=[]
	constructor(Options:Options) {
		this.Options = {
			DataDir: '/var/lib/registry',
			...Options
		}
		if (!Options.Debug)
			this.Debug = (...args:any[])=>{}
		Options.Express.post('/v2/*/blobs/uploads/', this.StartUploadBlob.bind(this))
		Options.Express.put('/v2/*/blobs/uploads/:1', this.UploadBlob.bind(this))
		Options.Express.patch('/v2/*/blobs/uploads/:1', this.UploadBlob.bind(this))
		Options.Express.post('/v2/*/blobs/uploads/:1', this.UploadBlob.bind(this))
		Options.Express.head('/v2/*/blobs/:1', this.GetBlob.bind(this))
		Options.Express.get('/v2/*/blobs/:1', this.GetBlob.bind(this))
		Options.Express.put('/v2/*/manifests/:1', this.PutManifest.bind(this))
		Options.Express.get('/v2/*/manifests/:1', this.GetManifest.bind(this))
		Options.Express.use('/v2/', this.VersionCheck.bind(this))	
		setInterval(()=>this.GC(), 300*1000)
		setTimeout(()=>this.GC(), 5*1000)
		fsP.mkdir((this.Options.DataDir||'/var/lib/registry') + '/data', {recursive: true})
	}
	async Authenticate(Resource:string[], req:any, res:any) {
		if (!this.Options.AuthFunction) {
			this.Debug('Authenticate', Resource, true)
			return true
		}
		try {
			if (await this.Options.AuthFunction(Resource, "", "")) {
				this.Debug('Authenticate', "Anonymous", Resource, true)
				return true
			}
			if (req.headers.authorization?.toLowerCase().startsWith('basic')) {
				const Pass64 = req.headers.authorization.substring(6)
				const PassString = atob(Pass64)
				const Username = PassString.substring(0, PassString.indexOf(':'))
				const Password = PassString.substring(PassString.indexOf(':') + 1)
				if (await this.Options.AuthFunction(Resource, Username, Password)) {
					this.Debug('Authenticate', Username, Resource, true)
					return true
				}
			}
		} catch (e) {}
		res.set('WWW-Authenticate' ,'Basic realm="Docker Registry"')
		res.status(401)
		res.end()
		this.Debug('Authenticate', Resource, false)
		return false
	}

	async VersionCheck(req:any, res:any, skip:Function) {
		res.set('Docker-Distribution-API-Version', 'registry/2.0')
		if (!await this.Authenticate([], req, res)) return
		if (req.url == '/') {
			this.Debug('VersionCheck', req.url)
			res.send('{}')
			res.end()
		} else {
			this.Debug('404', req.url)
			res.status(404).send(JSON.stringify({
					"errors": [
						{
							"code": 404,
							"message": "Not Found",
						}
					]
			}))
			res.end()
		}
	}
	async StartUploadBlob(req:any, res:any, skip:Function) {
		res.set('Docker-Distribution-API-Version', 'registry/2.0')
		const Image = req.params[0]
		if (!await this.Authenticate(['Upload', Image], req, res)) return

		let UploadID = ''
		while (UploadID.length < 32 || this.Uploads[UploadID])
			UploadID += Math.random().toString(36).substring(2, 4)
		this.Uploads[UploadID] = {
			Image,
			UploadID,
			SHA256: new SHA256Thread(),
			Filename: this.Options.DataDir + '/upload.' + UploadID + '.tmp',
			LastActivity: new Date()
		}
		this.Debug('New Upload', Image, UploadID)
		res.set('Docker-Upload-UUID', UploadID)
		res.status(202).set('Location', '/v2/' + Image + '/blobs/uploads/' + UploadID)
		res.send()
		res.end()
	}
	async UploadBlob(req:any, res:any, skip:Function) {
		res.set('Docker-Distribution-API-Version', 'registry/2.0')
		const Image = req.params[0]
		if (!await this.Authenticate(['Upload', Image], req, res)) return

		let UploadID = req.params[1]
		this.Debug('Upload Data', Image, UploadID)
		const Upload = this.Uploads[UploadID]
		if (!Upload) {
			res.status(404)
			res.end()
			return
		}
		if (!Upload.File) {
			Upload.File = await fsP.open(Upload.Filename, 'a')
		}
		let Offset = 0
		let Length = parseInt(req.headers['content-length']) || 0
		if (req.headers['content-range']) {
			const Bits = req.headers['content-range'].split('-')
			if (Bits.length)
				Offset = parseInt(Bits[0])
			if (Bits.length > 1 && !Length)
				Length = parseInt(Bits[1])
			if ((await Upload.File.stat()).size != Offset - 1) {
				this.Debug('Invalid Offset', Image, UploadID)
				res.status(416).end()
				return
			}
		}
		const WriteLock = new Lock()
		let Cache = Buffer.from([])
		let GotLength = 0
		req.on('data', (data:Buffer)=>{
			Cache = Buffer.concat([Cache, data])
			Upload.LastActivity = new Date()
			if (Cache.length > 4*1024*1024) {
				const ToWrite = Cache
				Cache = Buffer.from([])
				WriteLock.Borrow().then(async (Done:Function)=>{
					await Upload.File.appendFile(ToWrite)
					Upload.SHA256.Append(ToWrite)
					GotLength += ToWrite.length
					Done()
				})
			}
		})
		req.on('end', async()=>{
			this.Debug('End Request')
			const Done = await WriteLock.Borrow()
			Upload.LastActivity = new Date()
			this.Debug('Got Lock')
			if (Cache.length) {
				await Upload.File.appendFile(Cache)
				Upload.SHA256.Append(Cache)
			}
			Cache=Buffer.from([])
			await Upload.File.sync()
			this.Debug('Flushed File')
			Upload.LastActivity = new Date()
			res.set('Range', '0-' + (await Upload.File.stat()).size)
			Upload.File.close()
			Upload.File = undefined
			if (req.query?.digest) {
				this.Debug('Checking Hash')
				const SHA256 = await Upload.SHA256.Sum()
				this.Debug(req.query.digest.substring(7), SHA256)
				if (req.query.digest.startsWith('sha256:') && req.query.digest.substring(7) == SHA256){
					this.Debug('Hash Valid')
					const NewFile = this.FilePath(Upload.Image, req.query?.digest)
					this.Debug('Moving temp file', Image, Upload.UploadID, req.query?.digest, path.basename(NewFile), NewFile)
					await fsP.mkdir(path.dirname(NewFile), {recursive: true})
					await fsP.rename(Upload.Filename, NewFile)
					this.Debug('Upload File Done', Image, Upload.UploadID, req.query?.digest, NewFile)
					res.status(202).end()
				} else {
					this.Debug('Upload Error!', Image, Upload.UploadID, req.query?.digest, Offset)
					res.status(500).end()
				}
				delete this.Uploads[UploadID]
			} else {
				this.Debug('Upload Chunk Done', Image, Upload.UploadID, GotLength + '/' + Length)
				res.status(202).end()
			}
		})
	}
	async GetBlob(req:any, res:any, skip:Function) {
		res.set('Docker-Distribution-API-Version', 'registry/2.0')
		const Image = req.params[0]
		const File = req.params[1]
		if (!await this.Authenticate(['Download', Image, File], req, res)) return
		const Filename = this.FilePath(Image, File)
		try {
			const Stat = await fsP.stat(Filename)
			res.set('Content-Length', Stat.size)
			if (File.startsWith('sha256:') != -1) {
				res.set('E-Tag', File)
			}
			if (req.method == 'GET') {
				const stream = fs.createReadStream(Filename)
				stream.pipe(res)
				this.Debug('BODY', Filename)
				return
			} else {
				this.Debug('HEAD', Filename)
				res.end()
			}
		}
		catch (e:any) {
			res.status(404).end()
			this.Debug('404', Filename)
			return
		}
	}
	async GC() {
		this.Debug('Running GC')
		const Files = await fsP.readdir(this.Options.DataDir||'.')
		for (let x in Files) {
			if (Files[x].startsWith('upload.')) {
				const Stat = await fsP.stat((this.Options.DataDir||'.') + '/' + Files[x])
				if (new Date().getTime() - Stat.mtime.getTime() > 300*60*1000) {
					this.Debug(Files[x], Stat)
					fsP.rm((this.Options.DataDir||'.') + '/' + Files[x])
				}
			}
		}
		for (let x in this.Uploads) {
			if (new Date().getTime() - this.Uploads[x].LastActivity.getTime() > 120*1000) {
				this.Uploads[x].File?.close()
				fsP.rm(this.Uploads[x].Filename)
				delete this.Uploads[x]
			}
		}
		const Blobs:any[] = []
		const Collect = async (Path:string)=>{
			this.Debug('GC', Path)
			const Files = await fsP.readdir(Path)
			for (let x in Files) {
				const Stats = await fsP.stat(Path + '/' + Files[x])
				if (Stats.isDirectory()) {
					await Collect(Path + '/' + Files[x])
				} else if (Path.endsWith('/manifest') && Files[x].endsWith('.dat')) {
					const FilePath = Path + '/' + Files[x]
					try {
						let ImageString = Path.substr((this.Options.DataDir||'').length)
						while (ImageString.startsWith('/'))
							ImageString = ImageString.substr(1)
						ImageString = ImageString.substr(5, ImageString.length - 14)
						const Content = (await fsP.readFile(FilePath)).toString()
						const Manifest = JSON.parse(Content)
						const ConfigBlobPath = this.FilePath(ImageString, Manifest.config.digest)
						this.Debug(ImageString, Manifest.config.digest, ConfigBlobPath)
						let Count = 0
						let GotAllFiles = true
						for (let L in Manifest.layers) {
							const Layer = Manifest.layers[L]
							const BlobPath = this.FilePath(ImageString, Layer.digest)
//							this.Debug(ImageString, Layer.digest, BlobPath)
							if (!Files[x].startsWith('sha256')) {
								Blobs.push(BlobPath)
							}
							try {
								const Stats = await fsP.stat(BlobPath)
								if (!Stats.isFile()) {
									GotAllFiles = false
								}
							} catch (e) {
								GotAllFiles = false
							}
							Count++
						}
						if (GotAllFiles) {
							Blobs.push(ConfigBlobPath)
						} else if (Files[x].startsWith('sha256')) {
							this.ReapQueue.push({
								ReapAt: new Date(new Date().getTime() + 60*1000),
								File: FilePath
							})
							this.ReapQueue.push({
								ReapAt: new Date(new Date().getTime() + 60*1000),
								File: FilePath + ".type"
							})
						}
						this.Debug('Manifest', FilePath, Count, GotAllFiles)
					} catch (e) {	
					}
				}
			}
		}
		const Reap = async (Path:string)=>{
			this.Debug('Reap', Path)
			const Files = await fsP.readdir(Path)
			for (let x in Files) {
				const Stats = await fsP.stat(Path + '/' + Files[x])
				if (Files[x] != 'manifest' && Stats.isDirectory()) {
					await Reap(Path + '/' + Files[x])
				}
			}
			for (let x in Files) {
				const Stats = await fsP.stat(Path + '/' + Files[x])
				if (Stats.isFile()) {
					if (Blobs.indexOf(Path + '/' + Files[x]) > -1) {
//						this.Debug('Keeping', Path + '/' + Files[x])
					} else {
						if (!this.ReapQueue.filter((Obj)=>Obj.File==(Path + '/' + Files[x])).length) {
							this.Debug('Adding to Reap Queue', Path + '/' + Files[x])
							this.ReapQueue.push({
								ReapAt: new Date(new Date().getTime() + 30*60*1000),
								File: Path + '/' + Files[x]
							})
						}
					}
				}
			}
		}

		await Collect((this.Options.DataDir||'/var/lib/registry') + '/data')
		await Reap((this.Options.DataDir||'/var/lib/registry') + '/data')
		for (let x=0; x<this.ReapQueue.length; x++) {
			const Soul = this.ReapQueue[x]
			if (Blobs.indexOf(Soul.File) > -1) {
				for (let y in this.ReapQueue) {
					if (this.ReapQueue[y] == Soul) {
						this.Debug('Reincarnated', y, Soul.File)
					}
				}
			} else if (Soul.ReapAt.getTime() - new Date().getTime() < 1000) {
				this.Debug('Reaping', x, Soul.File)
				for (let y in this.ReapQueue) {
					if (this.ReapQueue[y] == Soul) {
						this.Debug('Deleted', y, Soul.File)
						this.ReapQueue.splice(parseInt(y), 1)
						await fsP.rm(Soul.File)
						x--
						break
					}
				}
			}
		}
	}
	async PutManifest(req:any, res:any, skip:Function) {
		res.set('Docker-Distribution-API-Version', 'registry/2.0')
		const Image = req.params[0]
		let Tag = req.params[1]
		if (!await this.Authenticate(['Upload', Image, Tag], req, res)) return
		this.Debug('PUT MANIFEST', Image, Tag, req.headers['content-type'])
		const Filename = this.FilePath(Image, 'manifest', Tag)
		await fsP.mkdir(path.dirname(Filename), {recursive: true})
		const TypeFileName = Filename + '.type'
		await fsP.writeFile(TypeFileName, req.headers['content-type'])
		const SHA256 = new SHA256Thread()
		let Content = ""
		req.on('data', (data:Buffer)=>{
			Content += data.toString()
			SHA256.Append(data)
		})
		req.on('end', async(data:Buffer)=>{
			await fsP.writeFile(Filename, Content)
			const Hash256 = await SHA256.Sum()
			const HashFilename = this.FilePath(Image, 'manifest', 'sha256:' + Hash256)
			await fsP.writeFile(HashFilename, Content)
			const HashTypeFileName = HashFilename + '.type'
			await fsP.writeFile(HashTypeFileName, req.headers['content-type'])
			res.set('Docker-Content-Digest', 'sha256:' + Hash256)
			res.status(202).end()
		})
	}
	async GetManifest(req:any, res:any, skip:Function) {
		res.set('Docker-Distribution-API-Version', 'registry/2.0')
		const Image = req.params[0]
		let Tag = req.params[1]
		try {
			if (!await this.Authenticate(['Download', Image, Tag], req, res)) return
			this.Debug('GET MANIFEST', Image, Tag)
			const Filename = this.FilePath(Image, 'manifest', Tag)
			const TypeFileName = Filename + '.type'
			const Content = await fsP.readFile(Filename)
			const ContentType = await fsP.readFile(TypeFileName)
			const SHA256 = new SHA256Thread()
			SHA256.Append(Content)
			res.set('Content-Type', ContentType)
			res.set('Content-Length', Content.length)
			res.set('Docker-Content-Digest', 'sha256:' + await SHA256.Sum())
			res.status(200).end(Content)
		} catch (e) {
			res.status(404).end("")
		}
	}
	FilePath(...Bits:any) {
		let Filename = 'data'
		for (let x in Bits) {
//			const Hash = crypto.createHash('md5')
//			Hash.update(Bits[x])
//			Filename += '/' + Hash.digest('hex')
			const Bit = Bits[x].replace(/[^a-zA-Z0-9]/g, '_')
			Filename += '/' + (''+Bit)
		}
		return this.Options.DataDir + '/' + Filename + '.dat'
	}
}
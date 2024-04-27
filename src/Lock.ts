export default class Lock {
    private Queue = new Promise((resolve:any)=>resolve())
	get Ready() {
		return this.Queue
	}
    async Borrow() {
        let Done:Function=()=>{}
        const Prev = this.Queue
        this.Queue = new Promise((resolve:any)=>Done=()=>resolve())
        await Prev
        return Done
    }
}
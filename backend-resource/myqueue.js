function QueueObject ( level=1, size=Math.pow(2,32)-1, circular=false ) {
	var queueFront, queueRear, queue;
	var queueType = { level: level, size: size, circular: circular }


	this.init = function () {
		queue = [];
		queueFront = [];
		queueRear = [];
		for (var i=0; i<queueType.level; i++) {
			queueRear[i] = queueType.size-1;
			queueFront[i] = queueType.size-1;
		}
	}

	this.push = function ( element ) {
		if ( this.isFull() ) {
			console.log('queue full');
			return;
		}

		queueRear[0] = queueRear[0] + 1;
		for (var i=0; i<queueRear.length; i++) {
			if ( queueRear[i] === queueType.size ) {
				queueRear[i] = 0;
				if ( queueRear[i+1] !== undefined ){
					queueRear[i+1]++;
				}
			}
		}
		
		var curLevel = queue, nextLevel;
		for (var i=queueRear.length-1; i>=0; i--) {
			if ( i !== 0 ) {
				if ( curLevel[queueRear[i]] === undefined ) {
					nextLevel = [];
					curLevel[queueRear[i]] = nextLevel;
				} else {
					nextLevel = curLevel[queueRear[i]];
				}
					curLevel = nextLevel;
			} else {
				curLevel.push(element);
			}
		}
		

		// queue[queueRear[2]] = queue[queueRear[2]] || [];
		// queue[queueRear[2]][queueRear[1]] = queue[queueRear[2]][queueRear[1]] || [];
		// queue[queueRear[2]][queueRear[1]][queueRear[0]] = element;
	}

	this.shift = function () {
		if ( this.isEmpty() ) {
			console.log('queue empyt');
			return;
		}
		var value;

		queueFront[0] = queueFront[0] + 1;
		for (var i=0; i<queueFront.length; i++) {
			if ( queueFront[i] === queueType.size ) {
				queueFront[i] = 0;
				if ( queueFront[i+1] !== undefined ){
					queueFront[i+1]++;
				}
			}
		}
		
		var curLevel = queue, nextLevel;
		for (var i=queueFront.length-1; i>=0; i--) {
			if ( i !== 0 ) {
				nextLevel = curLevel[queueFront[i]];
				curLevel = nextLevel;
			} else {
				value = curLevel[queueFront[i]];
				curLevel[queueFront[i]] = undefined;
			}
		}


		// value = queue[queueFront[2]][queueFront[1]][queueFront[0]];
		// queue[queueFront[2]][queueFront[1]][queueFront[0]] = undefined;
		return value;
	}

	this.isFull = function () {
		var sum = 0;
		for (var i=queueFront.length-1; i>=0; i--) {
			if ( i === 0) {
				if ( (queueFront[i] - 1) === queueRear[i] ) sum++;
			} else {
				if ( queueFront[i] === queueRear[i] ) sum++;
			}
		}
		if ( sum === queueFront.length ) return true;
		return false;




		// if ( queueFront[2] === queueRear[2] )
		// 	if ( queueFront[1] === queueRear[1] )
		// 		if ( (queueFront[0] - 1) === queueRear[0] )
		// 			return true;
		// return false;
	}

	this.isEmpty = function () {
		var sum = 0;
		for (var i=queueFront.length-1; i>=0; i--) {
			if ( queueFront[i] === queueRear[i] ) sum++;
		}
		if ( sum === queueFront.length ) return true;
		return false;


		// if ( queueFront[2] === queueRear[2] )
		// 	if ( queueFront[1] === queueRear[1] )
		// 		if ( queueFront[0] === queueRear[0] )
		// 			return true;
		// return false;
	}

	this.init();
	this.queue = queue;
	// this.front = queueFront;
	// this.rear = queueRear;
}

module.exports = QueueObject;
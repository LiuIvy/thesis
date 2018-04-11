const deepcopy = require('deepcopy');
const _ = require('underscore');


/*	[checkObjectIsEmpty]
 *	
 */
function checkObjectIsEmpty ( obj ) {
	// null and undefined are "empty"
	if (obj == null) return true;
	// Assume if it has a length property with a non-zero value
	// that that property is correct.
	if (obj.length > 0)    return false;
	if (obj.length === 0)  return true;
	// If it isn't an object at this point
	// it is empty, but it can't be anything *but* empty
	// Is it empty?  Depends on your application.
	if (typeof obj !== "object") return true;
	// Otherwise, does it have any properties of its own?
	// Note that this doesn't handle
	// toString and valueOf enumeration bugs in IE < 9
	for (var key in obj) {
		if (hasOwnProperty.call(obj, key)) return false;
	}
	return true;
}

function checkElementIsExistInArray ( item, list ) {
	for (let curItemCount=0; curItemCount<list.length; curItemCount++) {
		let curItem = list[curItemCount];
		if ( _.isEqual(item, curItem) )
			return true;
	}

	// list.forEach(function ( curItem, curItemCount ) {
	// 	if ( curItem == item ) return true;
	// });
	return false;
}



/*	[randomValue]
 *	
 */
function randomValue ( low, high, show=false ) {
	let value = Math.floor(( Math.random() * (high - low + 1) ) + low);
	if ( show === true )
		console.log(`low: ${low}, high: ${high}, random: ${value}`);
    return value;
}



/*	[ipConvertor]
 *	If input data is a string to express IP address, it will return in value.
 *	Otherwise, it will return a IP address as 'X.X.X.X'.
 */
function ipConvertor ( ipData ) {
	if ( !isNaN(ipData) ) {
		let Quotient = [],
			Remainder = [];

		Quotient[0] = ipData;
		for (var i = 0; i < 4; i++) {
			Remainder[i] = Math.floor( Quotient[i] % 256 );
			Quotient[i+1] = Math.floor( Quotient[i] / 256 );
		}

		let mask = Remainder[3];
		for (var i = 2; i >= 0; i--)
			mask = mask + '.' + Remainder[i];
		return mask;
	} else {
		let ipSplit = ipData.trim().split('.');
		return ( ( ((+ipSplit[0]) * 256) + (+ipSplit[1]) ) * 256 + (+ipSplit[2]) ) * 256 + (+ipSplit[3]);
	}
}



/*	[AddressPrefixObject Constructor]
 *	@ parameter
 *	ipdata:	ip information, express as a string like 'X.X.X.X/X'.
 *	
 *	@ output
 *	Return a object which contain with,
 *	maskData:		a value from 0 to 32, original value from calling function.
 *	ipaddrData:		a ip address data, original string from calling function.
 *	maskAddress:	a string to express network mask as 'X.X.X.X'
 *	maskNumber:		a value in decimal to express network mask, according to 'maskAddress'.
 *	ipMinAddress:	a string to express network address as 'X.X.X.X'
 *	ipMinNumber:	a value in decimal to express network address, according to 'maskAddress'.
 *	ipMaxAddress:	a string to express boardcast address as 'X.X.X.X'
 *	ipMaxNumber:	a value in decimal to express boardcast address, according to 'maskAddress'.
 */
function AddressPrefixObject ( ipdata ) {
	let [ipaddr, mask] = ipdata.trim().split('/');
	this.maskData = mask;
	this.ipaddrData = ipaddr;
	this.maskNumber = ( parseInt('1'.repeat(mask), 2) << 32-mask ) >>> 0;
	this.maskAddress = ipConvertor(this.maskNumber);
	this.ipMinNumber = ((ipConvertor(ipaddr)) & (this.maskNumber)) >>> 0;
	this.ipMinAddress = ipConvertor(this.ipMinNumber);
	this.ipMaxNumber = ((this.ipMinNumber >>> 0) | (parseInt(('1'.repeat(32-mask)), 2))) >>> 0;
	this.ipMaxAddress = ipConvertor(this.ipMaxNumber);

	// return this;
}
function PortSplit(portdata)
{	
	let [minport, maxport] = portdata.trim().split(':');
	this.portMinNumber = minport;
	this.portMaxNumber = maxport;
}

function isValidIPAddr_v4 ( ipaddress ) {
	return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress);
}
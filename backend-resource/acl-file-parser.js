// "use strict";
const fs = require('fs');
const Getopt = require('node-getopt').create([
		['A', '=' 				, 'append rule to table option.'],
		['I', '=' 				, 'insert rule to table option.'],
		['i', '=' 				, 'interface to set inbound option.'],
		['o', '=' 				, 'interface to set outbound option.'],
		['p', '=' 				, 'protocol option.'],
		['s', '=' 				, 'source IP option.'],
		['', 'sport=ARG'		, 'source port option.'],
		['d', '=' 				, 'destination IP option.'],
		['', 'dport=ARG'		, 'destination port option.'],
		['', 'tcp-flags=ARG'	, 'TCP flag option.'],
		['j', '=' 				, 'action option.']
		]).bindHelp();



/*	[ACLFileObject Constructor]
 *	@ parameter
 *	cmdDataLine:	the file path of acl file to be convert
 *	
 *	@ output
 *	Return a object which contain below parameter,
 *	errList:	a list consist of error in the original file 
 *	cmdList:	a list consist of 
 *	ruleList:	a list consist of rule which been convert
 *	ruleObject:	
 */
function ACLFileObject ( curObjName, cmdDataLine=null ) {
	let errList = [],
		cmdList = [],
		cmdListByData = {},
		ruleList = [],
		ruleObject = {};

	// do when a node is created to diagram.
	if ( cmdDataLine === null ) {
		// this.cmdList = cmdList;
		// this.cmdListByData = cmdListByData;
		this.ruleList = ruleList;
		this.ruleObject = ruleObject;
		this.nodeName = curObjName;
		return;
		// return this;
	}

	// lineList = fs.readFileSync(cmdDataLine, 'utf-8').toString().split('\n');
	cmdDataLine.forEach(function ( line, lineCount ) {
		let rule = cmdParser(line, lineCount, function ( err ) {
			if ( err ) { errList.push(err); } 
		});
		if ( checkObjectIsEmpty(rule) ) { return; }
		let interface = rule['interface'],
			in_out = rule['in_out'];
		
		ruleObject[interface] = ruleObject[interface] || {};
		ruleObject[interface][in_out] = ruleObject[interface][in_out] || [];
		rule['ruleOrder'] = ruleObject[interface][in_out].length;
		// rule['mode'] = 'normal';
		rule['nodeName'] = curObjName;
		ruleObject[interface][in_out].push(rule);
		ruleList.push(rule);
	});

	if ( errList.length > 0 ) {
		// console.log(errList);
		this.errList = errList;
	}
	// this.cmdList = cmdList;
	// this.cmdListByData = cmdListByData;
	this.ruleList = ruleList;
	this.ruleObject = ruleObject;
	this.nodeName = curObjName;
	return;
}

function cmdParser ( line, lineCount, callback ) {
	let splitLine = line.trim().split(' ');
	let lineOption = Getopt.parse(splitLine);
	let action, dest_ip, src_ip, in_out, interface, protocol, src_port, dest_port, tcp_flags = [];
	let err;

	if ( !checkSyntax(lineOption['argv']) ) {
		err = `[cmdParser] [line:${lineCount+1}] is not a iptables commad.`;
		callback(err);
	}
	// else console.log(`[${lineCount}] ${lineOption['argv']}`);

	if ( lineOption['options']['A'] === 'INPUT' || lineOption['options']['I'] === 'INPUT' ) {
		if ( lineOption['options']['o'] ) {
			err = `[cmdParser] Append or insert to INPUT, but options of interface is '-o'.`;
			callback(err);
		}
		interface = lineOption['options']['i'];
		in_out = lineOption['options']['A'] ? lineOption['options']['A'] : lineOption['options']['I'];
	} else if ( lineOption['options']['A'] === 'OUTPUT' || lineOption['options']['I'] === 'OUTPUT' ) {
		if ( lineOption['options']['i'] ) {
			err = `[cmdParser] [line:${lineCount+1}] Append or insert to OUTPUT, but options of interface is '-i'.`;
			callback(err);
		}
		interface = lineOption['options']['o'];
		in_out = lineOption['options']['A'] ? lineOption['options']['A'] : lineOption['options']['I'];
	}

	if ( lineOption['options']['tcp-flags'] ) {
		tcp_flags = lineOption['argv'][1].trim().split(',');
		protocol = 'tcp';
		tcp_flags = tcp_flags;
	} else if ( lineOption['options']['p'] ) {
		protocol = lineOption['options']['p'];
		tcp_flags = tcp_flags;
	} else {
		protocol = 'ip';
		tcp_flags = tcp_flags;
	}

	if ( lineOption['options']['s'] ) { src_ip = lineOption['options']['s']; }
	else { src_ip = '0.0.0.0/0'; }

	if ( lineOption['options']['d'] ) { dest_ip = lineOption['options']['d']; }
	else { dest_ip = '0.0.0.0/0'; }
	

	src_port = lineOption['options']['sport'];
	dest_port = lineOption['options']['dport'];
	
	action = lineOption['options']['j'];


	if ( err ) return;

	return (new RuleObject(lineCount, interface, in_out, src_ip, dest_ip, protocol, src_port, dest_port, tcp_flags, action));

	function checkSyntax ( splitLine ) {
		let currentOffset = splitLine.indexOf('iptables');
		if ( currentOffset != 0 ) return false;
		// offset splitLine if needed.
		// if ( currentOffset > 0) splitLine = splitLine.slice(currentOffset);
		return true;
	}
}




function RuleObject ( listOrder, interface, in_out, src_ip, dest_ip, protocol, src_port, dest_port, tcp_flags, action, isExchange=false ) {
	this.interface = interface;
	this.in_out = in_out;
	this.src_ip = src_ip;
	this.dest_ip = dest_ip;
	this.protocol = protocol;
	this.src_port = src_port;
	this.dest_port = dest_port;
	this.tcp_flags = tcp_flags;
	this.action = action;
	this.isExchange = isExchange;
	this.ruleOrder = undefined;
	this.listOrder = listOrder;

	return this;
}

















/*	[RuleObject Constructor]
 *	@ parameter
 *	line:		the main input data for this function, iptables commad line.
 *	lineCount:	counter of the input command line, need to pass by user.
 *	callback:	callback function, major to print error information.
 *	
 *	@ output
 *	Return a object which contain with,
 *	rulemode:	will be fill by calling function.
 *	ruleorder:	will be fill by calling function.
 *	lineorder:	the line order of original file, according to 'lineCount'.
 *	interface:	the interface of the rule be used, according to 'line'.
 *	in_out:		INPUT or OUTPUT chain is the rule be used, according to 'line'.
 *	protocol:	protocol of the rule, if tcp-flags is exist, this will be 'tcp'. According to 'line'.
 *	tcp_flags:	if exist, this will be a array with specify flags. Otherwise, it will be a empty array. According to 'line'.
 *	src_ip:		a AddressPrefixObject with source IP and mask information
 *	dest_ip:	a AddressPrefixObject with destination IP and mask information
 *	src_port:	source port information
 *	dest_port:	destination port information
 *	action:		the corresponding action of the rule, according to 'line'.
 */
// function RuleObject ( line, lineCount, callback ) {
// 	let splitLine = line.trim().split(' ');
// 	let lineOption = Getopt.parse(splitLine);
// 	let tcp_flags = [], sip, dip, err;

// 	this.rulemode;
// 	this.ruleorder;
// 	this.lineorder = lineCount;

// 	// fill the 'interface' and 'in_out' to this object
// 	if ( lineOption['options']['A'] === 'INPUT' || lineOption['options']['I'] === 'INPUT' ) {
// 		if ( lineOption['options']['o'] ) {
// 			err = `[RuleObject] Append or insert to INPUT, but options of interface is '-o'.`;
// 			callback(err);
// 		}
// 		this.interface = lineOption['options']['i'];
// 		this.in_out = lineOption['options']['A'] ? lineOption['options']['A'] : lineOption['options']['I'];
// 	} else if ( lineOption['options']['A'] === 'OUTPUT' || lineOption['options']['I'] === 'OUTPUT' ) {
// 		if ( lineOption['options']['i'] ) {
// 			err = `[RuleObject] [line:${lineCount+1}] Append or insert to OUTPUT, but options of interface is '-i'.`;
// 			callback(err);
// 		}
// 		this.interface = lineOption['options']['o'];
// 		this.in_out = lineOption['options']['A'] ? lineOption['options']['A'] : lineOption['options']['I'];
// 	}
	
// 	// fill the 'protocol' and 'tcp_flags' to this object
// 	if ( lineOption['options']['tcp-flags'] ) {
// 		tcp_flags = lineOption['argv'][1].trim().split(',');
// 		this.protocol = 'tcp';
// 		this.tcp_flags = tcp_flags;
// 	} else if ( lineOption['options']['p'] ) {
// 		this.protocol = lineOption['options']['p'];
// 		this.tcp_flags = tcp_flags;
// 	} else {
// 		this.protocol = 'ip';
// 		this.tcp_flags = tcp_flags;
// 	}

// 	// fill the 'src_ip' to this object
// 	if ( lineOption['options']['s'] ) { sip = lineOption['options']['s']; }
// 	else { sip = '0.0.0.0/0'; }
// 	this.src_ip = new AddressPrefixObject(sip);

// 	// fill the 'dest_ip' to this object
// 	if ( lineOption['options']['d'] ) { dip = lineOption['options']['d']; }
// 	else { dip = '0.0.0.0/0'; }
// 	this.dest_ip = new AddressPrefixObject(dip);
	

// 	this.src_port = lineOption['options']['sport'];
// 	this.dest_port = lineOption['options']['dport'];
	
// 	// fill the 'protocol' and 'tcp_flags' to this object
// 	this.action = lineOption['options']['j'];

// 	if ( err ) {
// 		// console.log(`[${lineCount}] err`);
// 		for (let key in this) {
// 			delete this[key];
// 		}
// 	}
// }


module.exports = ACLFileObject;
module.exports.RuleObject = RuleObject;

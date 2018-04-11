const deepcopy = require('deepcopy');
const QueueObject = require('./myqueue.js');
const RuleObject = require('./acl-file-parser.js').RuleObject;

function ARARTree ( inputData, segmentMode=false, useExchange=true, initialLevel=1 ) {
	let createTime, startTime, endTime;
	let treeRoot, node, ruleList = [], leafList = [];
	let queue = new QueueObject(3, Math.pow(2,32)-1, true);
	let exchangedInputData;

	
	// if need to exchange
	if ( useExchange ) {
		exchangedInputData = exchangeRuleList(inputData);
		for (var i = 0; i < inputData.length; i++) {
			ruleList.push(inputData[i]);
			ruleList.push(exchangedInputData[i]);
		}
	}
	// console.log(ruleList);
	
	
	// convert the ruleList
	ruleList = inputDataConvertor(ruleList);
	console.log(ruleList);
	
	

	// start to build tree
	treeRoot = new ARARNode(segmentMode);
	treeRoot['ruleList'] = ruleList;
	treeRoot['parameter'] = getRSV(treeRoot['ruleList'], initialLevel);
	if ( segmentMode ) {
		for (let i=0; i<treeRoot['ruleList'].length; i++) {
			if ( treeRoot['ruleList'][i]['flag'] === true ) {
				treeRoot['flag'] = true;
				break;
			}
		}
	}

	startTime = process.hrtime();
	queue.push(treeRoot);
	while ( true ) {
		node = segmentation(queue.shift(), segmentMode, initialLevel);
		if ( node ) {
			let childSum = 0;
			if ( node['node00'] ) { queue.push(node['node00']); childSum++; }
			if ( node['node01'] ) { queue.push(node['node01']); childSum++; }
			if ( node['node10'] ) { queue.push(node['node10']); childSum++; }
			if ( node['node11'] ) { queue.push(node['node11']); childSum++;	}

			if ( (childSum === 0) && (node['ruleList'].length > 0) ) {
				let newDataList = [];
				node['ruleList'].forEach(function ( data ) {
					let newData;
					if ( useExchange ) {
						if ( data['mode'] ) {
							newData = exchangedInputData[data['listOrder']];
						} else {
							newData = inputData[data['listOrder']];
						}
						newDataList.push(newData);
					} else {
						newData = inputData[data['listOrder']];
						newDataList.push(newData);
					}
				});
				node['ruleList'] = newDataList;
				leafList.push(node);
			}
		} else break;
	}
	
	createTime = process.hrtime(startTime);
	console.log(`createTime: ` + (createTime[0] + createTime[1]/1e9) + `sec`);
	console.log(leafList.length);

	// this.treeRoot = treeRoot;
	this.leafList = leafList;
}




/*	[ARARRule Constructor]
 *	@ parameter
 */
function ARARRule ( listOrder, min_sip, max_sip, min_dip, max_dip, flag, mode ) {
	this.listOrder = listOrder;
	this.min_sip = min_sip;
	this.max_sip = max_sip;
	this.min_dip = min_dip;
	this.max_dip = max_dip;
	this.flag = flag;
	this.mode = mode;
}

function ARARNode ( segmentMode, parameter=undefined ) {
	this.parameter = parameter;
	this.node00 = undefined;
	this.node01 = undefined;
	this.node10 = undefined;
	this.node11 = undefined;
	this.ruleList = [];
	if ( segmentMode ) this.flag = false;
}

function ARARParameter ( rsvSrc, rsvDest, baseSrc, baseDest, nodeLevel, segTimes ) {
	this.rsvSrc = rsvSrc;
	this.rsvDest = rsvDest;
	this.baseSrc = baseSrc;
	this.baseDest = baseDest;
	this.nodeLevel = nodeLevel;
	this.segTimes = segTimes;
}


function initialRSV ( data, segTimes=1 ) {
	// console.log('initialRSV', data);
	let maxSIP = data[0]['max_sip'];
	let minSIP = data[0]['min_sip'];
	let maxDIP = data[0]['max_dip'];
	let minDIP = data[0]['min_dip'];
	let MASK = Math.pow(2, 32) - 1;		//	= 255.255.255.255
	let tempSrc, tempDest, tempValue, baseSrc, baseDest;
	let rsvSrc, rsvDest, nodeLevel;
	
	for ( let i = 1; i < data.length; i++) {
		if ( maxSIP < data[i]['max_sip'] )
			maxSIP = data[i]['max_sip'];
		if ( maxDIP < data[i]['max_dip'] )
			maxDIP = data[i]['max_dip'];
		if ( minSIP > data[i]['min_sip'] )
			minSIP = data[i]['min_sip'];
		if ( minDIP > data[i]['min_dip'] )
			minDIP = data[i]['min_dip'];
	};
	// console.log(minSIP, ipConvertor(minSIP));
	// console.log(maxSIP, ipConvertor(maxSIP));
	// console.log(minDIP, ipConvertor(minDIP));
	// console.log(maxDIP, ipConvertor(maxDIP));

	tempSrc = Math.floor(Math.log2((maxSIP ^ minSIP) >>> 0));
	// console.log('tempSrc: ', tempSrc);
	tempDest = Math.floor(Math.log2((maxDIP ^ minDIP) >>> 0));
	// console.log('tempDest: ', tempDest);
	tempValue = (tempSrc > tempDest) ? tempSrc : tempDest;
	// console.log('tempValue: ', tempValue);

	rsvSrc = Math.pow(2, tempValue);
	rsvDest = Math.pow(2, tempValue);
	nodeLevel = 32 - tempValue;
	// console.log('rsvSrc: ', rsvSrc);

	if ( (tempValue + 1) !== 32 ) {
		baseSrc = (minSIP & ((MASK << (tempValue + 1)) >>> 0)) >>> 0;
		baseDest = (minDIP & ((MASK << (tempValue + 1)) >>> 0)) >>> 0;
	} else {
		baseSrc = (minSIP & 0) >>> 0;
		baseDest = (minDIP & 0) >>> 0;
	}

	return new ARARParameter(rsvSrc, rsvDest, baseSrc, baseDest, nodeLevel, segTimes);
}

function updateRSV ( data, parameter ) {
	// console.log('updateRSV');
	let newParameter = new ARARParameter(parameter['rsvSrc'], parameter['rsvDest'], parameter['baseSrc'], parameter['baseDest'], parameter['nodeLevel'], parameter['segTimes']);


	if ( data[0]['min_sip'] < ((newParameter['rsvSrc'] | newParameter['baseSrc']) >>> 0) )
		newParameter['rsvSrc'] &= ( ~( 1 << (32 - newParameter['nodeLevel']) ) >>> 0 );
	newParameter['rsvSrc'] |= ( 1 << ((32 - newParameter['nodeLevel']) - 1) );
	
	if ( data[0]['min_dip'] < ((newParameter['rsvDest'] | newParameter['baseDest']) >>> 0 ) )
		newParameter['rsvDest'] &= ( ~( 1 << (32 - newParameter['nodeLevel']) ) >>> 0 );
	newParameter['rsvDest'] |= ( 1 << ((32 - newParameter['nodeLevel']) - 1) );

	newParameter['nodeLevel']++;
	newParameter['segTimes']++;
	
	return newParameter
}

function getRSV ( data, initialLevel, parameter=undefined ) {
	if ( parameter === undefined ) {
		return initialRSV( data );
	} else if ( parameter['segTimes'] <= initialLevel ) {
		return initialRSV(data, parameter['segTimes']+1);
	} else {
		return updateRSV(data, parameter);
	}
}

function segmentation ( node, segmentMode, initialLevel ) {
	if ( node === undefined ) return node;

	if ( segmentMode ) {
		if ( node['flag'] === false ) return node;
	}

	if ( !checkIsNodeNeedToDoSegmentation(node) ) return node;

	node['ruleList'].forEach(function ( curRule ) {
		let rsvSrcReal = (node['parameter']['baseSrc'] | node['parameter']['rsvSrc']) >>> 0;
		let rsvDestReal = (node['parameter']['baseDest'] | node['parameter']['rsvDest']) >>> 0;
		let newRule;

		let ruleLocate = [];
		ruleLocate[0] =  Math.floor( curRule['min_sip'] / rsvSrcReal );
		ruleLocate[1] =  Math.floor( curRule['max_sip'] / rsvSrcReal );
		ruleLocate[2] =  Math.floor( curRule['min_dip'] / rsvDestReal );
		ruleLocate[3] =  Math.floor( curRule['max_dip'] / rsvDestReal );
		// newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], curRule['max_sip'], curRule['min_dip'], curRule['max_dip'], curRule['flag'], curRule['mode']);
		switch ( ruleLocate.join('') ) {
			case '0000':
			/* case '0000'
			 *  -----------
			 * |     |     |
			 * |     |     |
			 * |-----+-----|
			 * | * * |     |
			 * | * * |     |
			 *  -----------
			 */
				if ( node['node00'] === undefined )
					node['node00'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( curRule['flag'] === true )
						node['node00']['flag'] = true;
				node['node00']['ruleList'].push(curRule);
				break;
			case '0011':
			/* case '0011'
			 *  -----------
			 * | * * |     |
			 * | * * |     |
			 * |-----+-----|
			 * |     |     |
			 * |     |     |
			 *  -----------
			 */
				if ( node['node01'] === undefined )
					node['node01'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( curRule['flag'] === true )
						node['node01']['flag'] = true;
				node['node01']['ruleList'].push(curRule);
				break;
			case '1100':
			/* case '1100'
			 *  -----------
			 * |     |     |
			 * |     |     |
			 * |-----+-----|
			 * |     | * * |
			 * |     | * * |
			 *  -----------
			 */
				if ( node['node10'] === undefined )
					node['node10'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( curRule['flag'] === true )
						node['node10']['flag'] = true;
				node['node10']['ruleList'].push(curRule);
				break;
			case '1111':
			/* case '1111'
			 *  -----------
			 * |     | * * |
			 * |     | * * |
			 * |-----+-----|
			 * |     |     |
			 * |     |     |
			 *  -----------
			 */	
				if ( node['node11'] === undefined )
					node['node11'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( curRule['flag'] === true )
						node['node11']['flag'] = true;
				node['node11']['ruleList'].push(curRule);
				break;
			case '0100':
			/* case '0100'
			 *  -----------
			 * |     |     |
			 * |     |     |
			 * |-----+-----|
			 * |   * | *   |
			 * |   * | *   |
			 *  -----------
			 */

				newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], (rsvSrcReal - 1), curRule['min_dip'], curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node00'] === undefined )
					node['node00'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node00']['flag'] = true;
				node['node00']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], rsvSrcReal, curRule['max_sip'], curRule['min_dip'], curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node10'] === undefined )
					node['node10'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node10']['flag'] = true;
				node['node10']['ruleList'].push(newRule);
				break;
			case '0001':
			/* case '0001'
			 *  -----------
			 * |     |     |
			 * | * * |     |
			 * |-----+-----|
			 * | * * |     |
			 * |     |     |
			 *  -----------
			 */
				newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], curRule['max_sip'], curRule['min_dip'], (rsvDestReal - 1), curRule['flag'], curRule['mode']);
				if ( node['node00'] === undefined )
					node['node00'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node00']['flag'] = true;
				node['node00']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], curRule['max_sip'], rsvDestReal, curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node01'] === undefined )
					node['node01'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node01']['flag'] = true;
				node['node01']['ruleList'].push(newRule);
				break;
			case '0111':
			/* case '0111'
			 *  -----------
			 * |   * | *   |
			 * |   * | *   |
			 * |-----+-----|
			 * |     |     |
			 * |     |     |
			 *  -----------
			 */
				newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], (rsvSrcReal - 1), curRule['min_dip'], curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node01'] === undefined )
					node['node01'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node01']['flag'] = true;
				node['node01']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], rsvSrcReal, curRule['max_sip'], curRule['min_dip'], curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node11'] === undefined )
					node['node11'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node11']['flag'] = true;
				node['node11']['ruleList'].push(newRule);
				break;
			case '1101':
			/* case '1101'
			 *  -----------
			 * |     |     |
			 * |     | * * |
			 * |-----+-----|
			 * |     | * * |
			 * |     |     |
			 *  -----------
			 */
			 	newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], curRule['max_sip'], curRule['min_dip'], (rsvDestReal - 1), curRule['flag'], curRule['mode']);
				if ( node['node10'] === undefined )
					node['node10'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node10']['flag'] = true;
				node['node10']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], curRule['max_sip'], rsvDestReal, curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node11'] === undefined )
					node['node11'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node11']['flag'] = true;
				node['node11']['ruleList'].push(newRule);
				break;
			case '0101':
			/* case '0101'
			 *  -----------
			 * |     |     |
			 * |   * | *   |
			 * |-----+-----|
			 * |   * | *   |
			 * |     |     |
			 *  -----------
			 */
			 	newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], (rsvSrcReal - 1), curRule['min_dip'], (rsvDestReal - 1), curRule['flag'], curRule['mode']);
				if ( node['node00'] === undefined )
					node['node00'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node00']['flag'] = true;
				node['node00']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], curRule['min_sip'], (rsvSrcReal - 1), rsvDestReal, curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node01'] === undefined )
					node['node01'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node01']['flag'] = true;
				node['node01']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], rsvSrcReal, curRule['max_sip'], curRule['min_dip'], (rsvDestReal - 1), curRule['flag'], curRule['mode']);
				if ( node['node10'] === undefined )
					node['node10'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node10']['flag'] = true;
				node['node10']['ruleList'].push(newRule);

				newRule = new ARARRule(curRule['listOrder'], rsvSrcReal, curRule['max_sip'], rsvDestReal, curRule['max_dip'], curRule['flag'], curRule['mode']);
				if ( node['node11'] === undefined )
					node['node11'] = new ARARNode(segmentMode);
				if ( segmentMode )
					if ( newRule['flag'] === true )
						node['node11']['flag'] = true;
				node['node11']['ruleList'].push(newRule);
				break;

			default:
				break;
		}
	});
	node['ruleList'] = [];

	if ( node['node00'] !== undefined )
		node['node00']['parameter'] = new getRSV(node['node00']['ruleList'], initialLevel, node['parameter']);
	if ( node['node01'] !== undefined )
		node['node01']['parameter'] = new getRSV(node['node01']['ruleList'], initialLevel, node['parameter']);
	if ( node['node10'] !== undefined )
		node['node10']['parameter'] = new getRSV(node['node10']['ruleList'], initialLevel, node['parameter']);
	if ( node['node11'] !== undefined )
		node['node11']['parameter'] = new getRSV(node['node11']['ruleList'], initialLevel, node['parameter']);
	// console.log(node);
	return node;
}








function checkIsNodeNeedToDoSegmentation ( node ) {
	if ( node['ruleList'].length >= 2 )
		if ( checkRuleRangeIsDifferent(node['ruleList']) )
			return true;
	return false;

	function checkRuleRangeIsDifferent ( dataList ) {
		for (let i=0; i<dataList.length-1; i++) {
			if ( dataList[i]['max_sip'] != dataList[i+1]['max_sip'] ||
				 dataList[i]['max_dip'] != dataList[i+1]['max_dip'] ||
				 dataList[i]['min_sip'] != dataList[i+1]['min_sip'] ||
				 dataList[i]['min_dip'] != dataList[i+1]['min_dip'] ) {
				return true;
			}
		}
		return false;
	}
}

// function checkDoesNodeHaveSpecificFlag ( dataList ) {for(let i=0; i<dataList.length; i++) {if ( originalDataList[dataList[i]['listOrder']]['tcp_flags'].length > 0 ) {return true; } } return false; }






function inputDataConvertor ( dataList ) {
	let newDataList = [];
	// console.log(dataList);
	for (let dataCount=0; dataCount<dataList.length; dataCount++) {
		let data = dataList[dataCount];
		let newData, src_ip, dest_ip, flag = false;

		src_ip = new AddressPrefixObject(data['src_ip']);
		dest_ip = new AddressPrefixObject(data['dest_ip']);
		if ( data['tcp_flags'].length > 0 ) flag = true;
		newData = new ARARRule(data['listOrder'], src_ip['ipMinNumber'], src_ip['ipMaxNumber'], dest_ip['ipMinNumber'], dest_ip['ipMaxNumber'], flag, data['mode']);
		newDataList.push(newData);
	}
	return newDataList;
}

// function exchangeRuleList ( dataList ) {
// 	let newDataList = [];

// 	for (let dataCount=0; dataCount<dataList.length; dataCount++) {
// 		let data = dataList[dataCount];
// 		newDataList.push(data);
// 		let newData = new ARARRule(data['listOrder'], data['min_dip'], data['max_dip'], data['min_sip'], data['max_sip'], data['flag'], true);
// 		newDataList.push(newData);
// 	}
// 	return newDataList;
// }


function exchangeRuleList ( dataList ) {
	let newDataList = [];

	for (let dataCount=0; dataCount<dataList.length; dataCount++) {
		let data = dataList[dataCount];
		let newData = new RuleObject(data['listOrder'], data['interface'], data['in_out'], data['dest_ip'], data['src_ip'], data['protocol'], data['dest_port'], data['src_port'], data['tcp_flags'], data['action'], true);
		newData['nodeName'] = data['nodeName'];
		newDataList.push(newData);
	}
	return newDataList;
}


module.exports = ARARTree;
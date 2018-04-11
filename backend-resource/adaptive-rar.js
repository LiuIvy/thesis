function ARARTree ( inputData ) {
	let ruleList, parameter, treeRoot;

	ruleList = inputDataConvertor(inputData);
	console.log(ruleList);
	
	parameter = initialRSV(ruleList);
	console.log(parameter);

	treeRoot = startToCreate(ruleList, parameter);

	checkRuleAnomaly(treeRoot);

}


function ARARParameter ( rsvSrc, rsvDest, tmpSrc, tmpDest, max_sip, max_dip, nodeLevel ) {
	this.rsvSrc = rsvSrc;
	this.rsvDest = rsvDest;

	this.tmpSrc = tmpSrc;
	this.tmpDest = tmpDest;
	
	this.max_sip = max_sip;
	this.max_dip = max_dip;

	this.nodeLevel = nodeLevel;

	this.clone = function () { return new ARARNode(this.rsvSrc, this.rsvDest, this.tmpSrc, this.tmpDest, this.max_sip, this.max_dip, this.nodeLevel); }
}

function ARARNode ( rsvSrc, rsvDest, nodeLevel, ruleList=[] ) {
	this.rsvSrc = rsvSrc;
	this.rsvDest = rsvDest;
	this.nodeLevel = nodeLevel;
	this.node0 = undefined;
	this.node1 = undefined;
	this.ruleList = ruleList;

	this.clone = function () { return new ARARNode(this.rsvSrc, this.rsvDest, this.nodeLevel, this.ruleList); }
}

function ARARRule ( min_sip, max_sip, min_dip, max_dip ) {
	this.max_sip = max_sip;
	this.min_sip = min_sip;
	this.max_dip = max_dip;
	this.min_dip = min_dip;

	this.clone = function () { return new ARARRule(this.min_sip, this.max_sip, this.min_dip, this.max_dip); }
}

function TempRule ( value1=undefined, value2=undefined, value3=undefined, value4=undefined, block1=undefined, block2=undefined, mode=undefined ) {
	this.value1 = value1;
	this.value2 = value2;
	this.value3 = value3;
	this.value4 = value4;

	this.block1 = block1;
	this.block2 = block2;

	this.mode = mode;

	this.clone = function () { return new TempRule(this.value1, this.value2, this.value3, this.value4, this.block1, this.block2) }
}


function startToCreate ( dataList, parameter ) {
	let rootSrc, rootDest, treeRoot;

	dataList.forEach(function ( data, dataCount ) {
		let tmpRule, calRule;

		tmpRule = segmantation(data, parameter, false, true);
		calRule = tmpRule.clone();
		calRule['value1'] = tmpRule['value1'];
		calRule['value2'] = tmpRule['value2'];
		rootSrc = insert(rootSrc, calRule, data, parameter, false);
		if ( tmpRule['mode'] === true ) {
			calRule['value1'] = tmpRule['value3'];
			calRule['value2'] = tmpRule['value4'];
			rootSrc = insert(rootSrc, calRule, data, parameter, false);
		}

		tmpRule = segmantation(data, parameter, true, true);
		calRule = tmpRule.clone();
		calRule['value1'] = tmpRule['value1'];
		calRule['value2'] = tmpRule['value2'];
		rootDest = insert(rootDest, calRule, data, parameter, true);
		if ( tmpRule['mode'] === true ) {
			calRule['value1'] = tmpRule['value3'];
			calRule['value2'] = tmpRule['value4'];
			rootDest = insert(rootDest, calRule, data, parameter, true);
		}
	});

	if ( rootSrc ) treeRoot.src = rootSrc;
	if ( rootDest ) treeRoot.dest = rootDest;
	return treeRoot;
}

function segmantation ( data, parameter, mode, isFirst ) {
	let tmpRule = new TempRule();

	if ( !mode ) {
		if ( isFirst ) {
			tmpRule['value1'] = data['min_sip'];
			tmpRule['value2'] = data['max_sip'];
			tmpRule['block1'] = tmpRule['value1'] / parameter['rsvSrc'];
			tmpRule['block2'] = tmpRule['value2'] / parameter['rsvSrc'];
		} else {
			tmpRule['value1'] = data['cutSmall'];
			tmpRule['value2'] = data['cutLarge'];
			tmpRule['block1'] = tmpRule['value1'] / parameter['rsvSrc'];
			tmpRule['block2'] = tmpRule['value2'] / parameter['rsvSrc'];
		}
	}
	if ( mode ) {
		if ( isFirst ) {
			tmpRule['value1'] = data['min_dip'];
			tmpRule['value2'] = data['max_dip'];
			tmpRule['block1'] = tmpRule['value1'] / parameter['rsvDest'];
			tmpRule['block2'] = tmpRule['value2'] / parameter['rsvDest'];
		} else {
			tmpRule['value1'] = data['cutSmall'];
			tmpRule['value2'] = data['cutLarge'];
			tmpRule['block1'] = tmpRule['value1'] / parameter['rsvDest'];
			tmpRule['block2'] = tmpRule['value2'] / parameter['rsvDest'];
		}
	}

	if ( tmpRule['block2'] == 2 ) {
		tmpRule['block2'] = 1;
	}

	if ( tmpRule['block1'] == tmpRule['block2'] ) {
		tmpRule['value3'] = 0;
		tmpRule['value4'] = 0;
		tmpRule['mode'] = false;
	} else if ( tmpRule['block1'] != tmpRule['block2'] ) {
		if ( !mode ) {
			tmpRule['mode'] = true;
			if ( tmpRule['value2'] == parameter['rsvSrc'] )
				tmpRule['mode'] = false;
			tmpRule['value4'] = tmpRule['value2'];
			tmpRule['value2'] = parameter['rsvSrc'] - 1;
			tmpRule['value3'] = parameter['rsvSrc'];
		} else if ( mode ) {
			tmpRule['mode'] = true;
			if ( tmpRule['value2'] == parameter['rsvDest'] )
				tmpRule['mode'] = false;
			tmpRule['value4'] = tmpRule['value2'];
			tmpRule['value2'] = parameter['rsvDest'] - 1;
			tmpRule['value3'] = parameter['rsvDest'];
		}
	}
	return tmpRule;
}

function insert ( node, calRule, data, parameter, mode ) {
	let newData = data.clone();
	newData['cutSmall'] = calRule['value1'];
	newData['cutLarge'] = calRule['value2'];

	if ( node === undefined ) {
		let newNode = new ARARNode(parameter['rsvSrc'], parameter['rsvDest'], parameter['nodeLevel']);
		newNode['ruleList'].push(newData);
		node = new ARARNode(parameter['rsvSrc'], parameter['rsvDest'], parameter['nodeLevel']);

		if ( !mode ) {
			if ( calRule['value1'] < parameter['rsvSrc'] ) {
				node['node0'] = newNode.clone();
			} else {
				node['node1'] = newNode.clone();
			}
		} else if ( mode ) {
			if ( calRule['value1'] < parameter['rsvDest'] ) {
				node['node0'] = newNode.clone();
			} else {
				node['node1'] = newNode.clone();
			}
		}
	} else {
		if ( ((!mode) && (calRule['value1'] < parameter['rsvSrc'])) || ((mode) && (calRule['value1'] < parameter['rsvDest'])) ) {
			if ( node['node0'] === undefined ) {
				console.log(`node is exist, but node['node0'] is undefined`);
				
				let newNode = new ARARNode(parameter['rsvSrc'], parameter['rsvDest'], parameter['nodeLevel']);
				newNode['ruleList'].push(newData);
				node['node0'] = newNode.clone();

				return node;
			} else {
				if ( node['node0']['ruleList'].length === 0 ) {
					let newParameter = parameter.clone();
					newParameter['nodeLevel'] = node['node0']['nodeLevel'];
					newParameter['rsvSrc'] = node['node0']['rsvSrc'];
					newParameter['rsvDest'] = node['node0']['rsvDest'];

					node['node0']['ruleList'].push(newData);
					node['node0'] = addStructure(node['node0'], newParameter, mode);
				} else {
					node['node0']['ruleList'].push(newData);

					if ( !checkIsRuleRangeSame(node['node0']['ruleList'], mode) ) {
						let newParameter = parameter.clone();
						newParameter = updateRSV(node['node0']['ruleList'][0], newParameter, mode);
						node['node0'] = restructure(node['node0'], newParameter, mode);
						node['node0']['ruleList'] = [];
					}
				}
				return node;
			}
		} else if ( ((!mode) && (calRule['value1'] < parameter['rsvSrc'])) || ((mode) && (calRule['value1'] < parameter['rsvDest'])) ) {
			if ( node['node1'] === undefined ) {
				console.log(`node is exist, but node['node1'] is undefined`);
				
				let newNode = new ARARNode(parameter['rsvSrc'], parameter['rsvDest'], parameter['nodeLevel']);
				newNode['ruleList'].push(newData);
				node['node1'] = newNode.clone();

				return node;
			} else {
				if ( node['node1']['ruleList'].length === 0 ) {
					let newParameter = parameter.clone();
					newParameter['nodeLevel'] = node['node1']['nodeLevel'];
					newParameter['rsvSrc'] = node['node1']['rsvSrc'];
					newParameter['rsvDest'] = node['node1']['rsvDest'];

					node['node1']['ruleList'].push(newData);
					node['node1'] = addStructure(node['node1'], newParameter, mode);
				} else {
					node['node1']['ruleList'].push(newData);

					if ( !checkIsRuleRangeSame(node['node1']['ruleList'], mode) ) {
						let newParameter = parameter.clone();
						newParameter = updateRSV(node['node1']['ruleList'][0], newParameter, mode);
						node['node1'] = restructure(node['node1'], newParameter, mode);
						node['node1']['ruleList'] = [];
					}
				}
				return node;
			}
		}
	}
	return node;
}

function addStructure ( node, parameter, mode ) {
	let tmpRuleList = node['ruleList'];
	node['ruleList'] = [];
	let tmpRule = segmantation(tmpRuleList[0], parameter, mode, false);
	let calRule = tmpRule.clone();
	calRule['value1'] = tmpRule['value1'];
	calRule['value2'] = tmpRule['value2'];
	node = insert(node, calRule, tmpRuleList[0], parameter, mode);

	if ( tmpRule['mode'] === true ) {
		calRule['value1'] = tmpRule['value3'];
		calRule['value2'] = tmpRule['value4'];
		node = insert(node, calRule, tmpRuleList[0], parameter, mode);
	}

	return node;
}

function restructure ( node, parameter, mode ) {
	let tmpRuleList = node['ruleList'];
	node = undefined;
	let tmpRule;
	for (let i=0; i<tmpRuleList.length; i++) {
		tmpRule = segmantation(tmpRuleList[0], parameter, mode, false);
		let calRule = tmpRule.clone();
		calRule['value1'] = tmpRule['value1'];
		calRule['value2'] = tmpRule['value2'];
		node = insert(node, calRule, tmpRuleList[0], parameter, mode);

		if ( tmpRule['mode'] === true ) {
			calRule['value1'] = tmpRule['value3'];
			calRule['value2'] = tmpRule['value4'];
			node = insert(node, calRule, tmpRuleList[0], parameter, mode);
		}
	}
	return node;
}

function checkIsRuleRangeSame ( dataList, mode ) {
	for (let i=0; i<dataList.length; i++) {
		if ( (dataList[i]['cutSmall'] != dataList[i+1]['cutSmall']) ||
			 (dataList[i]['cutLarge'] != dataList[i+1]['cutLarge']) ) {
			return false;
		}
	}

	return true;
}









function checkRuleAnomaly ( node ) {

}



function initialRSV ( dataList ) {	
	let rsvSrc, rsvDest, tmpSrc, tmpDest, max_sip, max_dip;
	for (let i=0; i<dataList.length; i++) {
		if ( i === 0 ) {
			max_sip = dataList[i]['max_sip'];
			max_dip = dataList[i]['max_dip'];
		} else {
			if ( max_sip < dataList[i]['max_sip'] ) max_sip = dataList[i]['max_sip'];
			if ( max_dip < dataList[i]['max_dip'] ) max_dip = dataList[i]['max_dip'];
		}

		rsvSrc = Math.pow(2, Math.floor(Math.log2(max_sip)));
		tmpSrc = Math.pow(2, Math.floor(Math.log2(max_sip)));
		rsvDest = Math.pow(2, Math.floor(Math.log2(max_dip)));
		tmpDest = Math.pow(2, Math.floor(Math.log2(max_dip)));
	}
	

	return new ARARParameter(rsvSrc, rsvDest, tmpSrc, tmpDest, max_sip, max_dip, 1);
}

function updateRSV (  ) {
	
}







function inputDataConvertor ( dataList ) {
	let newDataList = [];

	dataList.forEach(function ( data ) {
		let newData, src_ip, dest_ip;
		src_ip = new AddressPrefixObject(data['src_ip']);
		dest_ip = new AddressPrefixObject(data['dest_ip']);
		newData = new ARARRule(src_ip['ipMinNumber'], src_ip['ipMaxNumber'], dest_ip['ipMinNumber'], dest_ip['ipMaxNumber']);
		newDataList.push(newData);
	});

	return newDataList;
}



module.exports = ARARTree;
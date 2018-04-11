

function myTopology ( nodeDataArray, linkDataArray ) {
	let topoObject = {};
	let routeTree = {};
	let pathTree = {};
	let nodeNameList = [];
	let nodeArrayByCategory = {
		network: [],
		firewall: []
	};
	let nodeObjectByName = {};
	let generateObject = {};

	nodeDataArray.forEach(function ( curNode, curNodeCount ) {
		nodeArrayByCategory[curNode.category].push(curNode);
		nodeObjectByName[curNode.key] = curNode;

		// if ( curNode.category === 'firewall' ) 
		topoObject[curNode['key']] = [];
	});

	linkDataArray.forEach(function ( curLink, curLinkCount ) {
		let fromNodeName = curLink.from;
		let fromNode = nodeObjectByName[fromNodeName];
		let toNodeName = curLink.to;
		let toNode = nodeObjectByName[toNodeName];

		// if ( !isExistInList(nodeNameList, fromNodeName) ) {
		// 	nodeNameList.push(fromNodeName);
		// }
		// if ( !isExistInList(nodeNameList, toNodeName) ) {
		// 	nodeNameList.push(toNodeName);
		// }

		topoObject[fromNodeName].push(toNodeName);
		topoObject[toNodeName].push(fromNodeName);
	});


	// Object.keys(nodeArrayByCategory).forEach(function ( category ) {
		nodeArrayByCategory['network'].forEach(function ( fromNode ) {
			pathTree[fromNode.key] = {}
			nodeArrayByCategory['network'].forEach(function ( toNode ) {
				if ( fromNode === toNode ) return;
				// console.log(fromNode.key, toNode.key);
				// pathTree[`${fromNode.key}-${toNode.key}`] = findAllPath(fromNode.key, toNode.key);
				pathTree[fromNode.key][toNode.key] = findAllPath(fromNode.key, toNode.key);

			});
			
		});
	// });

	// convert the pathTree(only fw infomation) to routeTree(fw, interface and in_out information) 
	Object.keys(pathTree).forEach(function ( fromNode ) {
		routeTree[fromNode] = {}
		Object.keys(pathTree[fromNode]).forEach(function ( toNode ) {
			routeTree[fromNode][toNode] = [];
			pathTree[fromNode][toNode].forEach(function ( curPath ) {
				let curRoute = [];

				curPath.forEach(function ( curNode, curNodeCount ) {
					let preNode, nextNode, newNode;
					
					if ( curNodeCount === 0 ) { nextNode = curPath[curNodeCount+1]; }
					else if ( curNodeCount === (curPath.length)-1 ) { preNode = curPath[curNodeCount-1]; }
					else {
						preNode = curPath[curNodeCount-1];
						nextNode = curPath[curNodeCount+1];
					}

					if ( preNode !== undefined ) {
						newNode = new pathObject(curNode, topoObject[curNode].indexOf(preNode), 'INPUT');
						curRoute.push(newNode);

						generateObject[newNode.nodeName] = generateObject[newNode.nodeName] || {};
						generateObject[newNode.nodeName][newNode.interface] = generateObject[newNode.nodeName][newNode.interface] || [];
						generateObject[newNode.nodeName][newNode.interface].push({
							nodeName: newNode.nodeName,
							interface: newNode.interface,
							in_out: newNode.in_out,
							src_ip: nodeObjectByName[fromNode].address,
							dest_ip: nodeObjectByName[toNode].address
						});
					}
					if ( nextNode !== undefined ) {
						newNode = new pathObject(curNode, topoObject[curNode].indexOf(nextNode), 'OUTPUT');
						curRoute.push(newNode);

						generateObject[newNode.nodeName] = generateObject[newNode.nodeName] || {};
						generateObject[newNode.nodeName][newNode.interface] = generateObject[newNode.nodeName][newNode.interface] || [];
						generateObject[newNode.nodeName][newNode.interface].push({
							nodeName: newNode.nodeName,
							interface: newNode.interface,
							in_out: newNode.in_out,
							src_ip: nodeObjectByName[fromNode].address,
							dest_ip: nodeObjectByName[toNode].address
						});
					}

				});

				routeTree[fromNode][toNode].push(curRoute);
			});

		});
	});

	Object.keys(generateObject).forEach(function ( nodeName ) {
		if ( nodeObjectByName[nodeName].category === 'network' ) {
			delete generateObject[nodeName];
		}
	});

	// Object.keys(routeTree).forEach(function ( srcNode ) {
	// 	Object.keys(routeTree[srcNode]).forEach(function ( destNode ) {
	// 		routeTree[srcNode][destNode].forEach(function ( curRoute ) {
	// 			curRoute.forEach(function ( curItem ) {
	// 				let cmdLine = [];
	// 				generateObject[curItem.nodeName] = generateObject[curItem.nodeName] || {};
	// 				generateObject[curItem.nodeName][curItem.interface] = generateObject[curItem.nodeName][curItem.interface] || [];
	// 				cmdLine.push(curItem.nodeName);
	// 				cmdLine.push(curItem.interface);
	// 				cmdLine.push(curItem.in_out);
	// 				cmdLine.push(nodeObjectByName[srcNode].address);
	// 				cmdLine.push(nodeObjectByName[destNode].address);

	// 				generateObject[curItem.nodeName][curItem.interface].push(cmdLine);
	// 			});
	// 		});
	// 	});
	// });




	this.topoObject = topoObject;
	this.routeTree = routeTree;
	this.pathTree = pathTree;
	this.nodeArray = nodeObjectByName;
	this.linkArray = linkDataArray;
	this.generateObject = generateObject;
	this.showNode = function () {
		console.log(this.nodeArray);
	}
	this.showLink = function () {
		console.log(this.linkArray);
	}
	this.showTopo = function () {
		console.log('topoObject: ', this.topoObject);
	}
	this.showPath = function () {
		console.log('pathTree: ', this.pathTree);
		console.log('routeTree: ', this.routeTree);
	}
	this.show = function () {
		console.log(this.generateObject);
	}



	function findAllPath ( fromNode, toNode, curPath=[]) {
		// console.log(fromNode);
		if ( !(topoObject.hasOwnProperty(fromNode)) ) return [];
		
		curPath.push(fromNode);
		if ( fromNode == toNode ) return [curPath];
		
		let curPathList = [];
		for (let curNodeCount=0; curNodeCount<topoObject[fromNode].length; curNodeCount++) {
			let curNode = topoObject[fromNode][curNodeCount];
			if ( !checkElementIsExistInArray(curNode, curPath) ) {
				let newPathList = findAllPath(curNode, toNode, deepcopy(curPath));
				for (let newPathCount=0; newPathCount<newPathList.length; newPathCount++) {
					let newPath = newPathList[newPathCount];
					curPathList.push(newPath);
				}
			}
		}
		return curPathList;
	}

	function pathObject ( nodeName, interface=0, in_out ) {
		this.nodeName = nodeName;
		this.interface = interface;
		this.in_out = in_out;
	}

}

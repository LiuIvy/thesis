const ACLObject = require(`${__dirname}/backend-resource/acl-file-parser.js`);

function ruleGenerator ( aclObject, geneInfo, ruleNumber=25, rangeSize=0 ) {
	// console.log(aclObject);
	// console.log(geneInfo);
	

	Object.keys(geneInfo).sort().forEach(function ( curNode ) {

		// aclObject[curNode]['cmdList'] = [];
		let cmdList = [];
		Object.keys(geneInfo[curNode]).sort().forEach(function ( curIf ) {
			let policyList = [];
			geneInfo[curNode][curIf].forEach(function ( curPolicy ) {
				if ( !checkElementIsExistInArray(curPolicy, policyList) ) { 
					policyList.push(curPolicy);
					// console.log(`${curNode} ${curIf}: `, policyList);
					// console.log(`${curNode}-et${curIf}: `, curPolicy);
					ruleDevelop(curPolicy, ruleNumber, function ( cmd ) {
						//console.log(cmd);
						// aclObject[curNode]['cmdList'] = aclObject[curNode]['cmdList'] || [];
						// aclObject[curNode]['cmdList'].push(cmd);
						cmdList.push(cmd);
					});
				}
			});

		});
		aclObject[curNode] = new ACLObject(curNode, cmdList);
	});

	// console.log(geneInfo);


	function ruleDevelop( policy, ruleNumber, callback ) {
		// console.log(policy);
		let ruleCounter = [];
		let actions = ['ACCEPT', 'DROP'];
		// let statelessFlag = [['SYN'], ['SYN','ACK'], ['ACK'], ['FIN'], ['ACK','FIN'], ['RST']];
		let statelessFlag = ['SYN', 'SYN,ACK', 'ACK', 'FIN', 'ACK,FIN', 'RST'];
		while ( ruleNumber > 0 ) {
			let iii = 500;
			let count, maxValue,
				mode = randomValue(0, iii-1) % iii;
			switch ( mode ) {
				case 1:		// stateless mode
					maxValue = ( ruleNumber < 6 ) ? ruleNumber : 6;
					count = randomValue(1, maxValue);
					ruleCounter.push({mode: mode, count: count});
					ruleNumber -= count;
					break;

				// case 2:		// stateful mode
				// 	maxValue = ( ruleNumber < 2 ) ? ruleNumber : 2;
				// 	count = randomValue(1, maxValue);
				// 	ruleCounter.push({mode: mode, count: count});
				// 	ruleNumber -= count
				// 	break;

				default:	// any mode
					count = 1;
					ruleCounter.push({mode: mode, count: count});
					ruleNumber -= count
					break;
			}
		}

		ruleCounter.forEach(function ( curItem ) {
			let flagList = [];
			let cmd = `iptables`;
			let src_port, dest_port, tcp_flags;
			src_port = [];
			dest_port = [];
			tcp_flags = [];

			cmd += ` -A ${policy.in_out}`;
			if ( policy.in_out === 'INPUT' )
				cmd += ` -i`;
			else if ( policy.in_out === 'OUTPUT' )
				cmd += ` -o`;
			cmd += ` eth${policy.interface}`;
			cmd += ` -p tcp`;
			cmd += ` -s ${ipRandomization(policy.src_ip)}`;
			//cmd += ` -s 140.134.30.55/16`;
			if ( src_port )
				cmd += ` --sport ${portRandomization()}`;
			cmd += ` -d ${ipRandomization(policy.dest_ip)}`;
			//cmd += ` -d 140.134.30.88/16`;
			if ( dest_port )
				cmd += ` --dport ${portRandomization()}`;

			for (let i=curItem.count; i>0; i--) {
				let  newCmd = deepcopy(cmd);
				if ( curItem.mode === 1 ) {
					tcp_flags = statelessFlag[randomValue(0, statelessFlag.length-1)];
					while ( checkElementIsExistInArray(tcp_flags, flagList) ) {
						tcp_flags = statelessFlag[randomValue(0, statelessFlag.length-1)];
					}
					flagList.push(tcp_flags);
					newCmd += ` --tcp-flags SYN,ACK,FIN,RST ${tcp_flags}`;
				}
				newCmd += ` -j ${actions[randomValue(0, 2) % 2]}`;
				// console.log(newCmd);
				callback(newCmd);
			}

		});


		function ipRandomization ( ipData ) {
			let addr, min_ip, max_ip;
			let mask, maskValue, maxMask, maskSigma;
			let newAddr, newAddrValue, newMask, newMaskValue;
			[addr, mask] = ipData.split('/');
			maskValue = ( parseInt('1'.repeat(mask), 2) << 32-mask ) >>> 0;
			min_ip = ipConvertor(addr) & maskValue;
			max_ip = min_ip | ~(maskValue);
			newAddrValue = randomValue(min_ip, max_ip);

			// newMask = randomValue(parseInt(mask), 24);
			switch ( rangeSize ) {
				case '0':
					minMask = (parseInt(mask) + 4) >= 32 ? 32 : (parseInt(mask) + 4);
					maxMask = (minMask + 4) >= 32 ? 32 : (minMask + 4);

					newMask = randomValue(minMask, maxMask);
					break;

				case '1':
					newMask = (parseInt(mask) + 3) >= 32 ? 32 : (parseInt(mask) + 3);
					break;

				case '2':
					minMask = parseInt(mask);
					maxMask = (minMask + 2) >= 32 ? 32 : (minMask + 2);
					newMask = randomValue(minMask, maxMask);
					break;
			}

			newMaskValue = ( parseInt('1'.repeat(newMask), 2) << 32-newMask ) >>> 0;
			newAddr = ipConvertor(newAddrValue & newMaskValue);
			

			return `${newAddr}/${newMask}`;
		}

		function portRandomization()
		{
			var portvalue;
			var port = [randomValue(0, 65535), randomValue(0, 65535)]; //(0,65535)
			var min_port = port[0] < port[1] ? port[0] : port[1];
			var max_port = port[0] > port[1] ? port[0] : port[1];
			return `${min_port}:${max_port}` ;
		}
	}

}
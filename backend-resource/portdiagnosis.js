function redOrGreen (event) {
	let nodeName = (this.chart.renderTo.id).split('-')[1];
	let block = myObject['aclObject'][nodeName]['ARARTree']['leafList'][this.index];
	let curNode = myObject['aclObject'][nodeName];
	let index = this.index;
	console.log('thisindex',index);
	console.log('block',block);
	if(block['anomalyInfo']['anomaly']==true){
		console.log('event',event);
		createAnomalyChart(event);
	}
	else			
		doPort(block,curNode,index);
			
		
}

function doPort(portBlock,curNode,index){

	var portExtract = portExtractor(portBlock['ruleList']);
	var portVector = [putVector(portExtract[0]), putVector(portExtract[1])];
	var retMergedVector = merge(portVector);
	//console.log('retMergedVector',retMergedVector);
	var retAndvector = and(retMergedVector);
	var portleaf = bitOrder(retAndvector, portBlock['ruleList'] ,curNode['ruleList']);
	//console.log('retPortList', retPortList);
	//checkPortAnomaly(retPortList);
	//console.log('portBlock',portBlock['routeObject']);
	
	checkPortAnomaly(portleaf,portBlock);
	//console.log('thisindex',index);
	//anomaly(portleaf);
	let startTime = process.hrtime();
	//console.log('leaf',portleaf[0]['anomalyInfo']);

	depictportResult(index,portleaf);
	let createTime = process.hrtime(startTime);
	console.log(`anomaly: ` + (createTime[0] + createTime[1]/1e9));

}
function anomaly(portleaf){
	//console.log('portleaf',portleaf);
	_.each(portleaf,function(leaf,leafCount){
		leaf['anomalyInfo'] = {
			'anomaly': false,
			'shadowing': [],
			'redundancy': [],
			'normal' : [],			
		};
		//leaf['ruleList'].forEach(function(rule,ruleCount){
		if( leaf['ruleList'].length > 1){
			for(var i=0 ; i < leaf['ruleList'].length ; i++){
				for(var j = i+1 ; j < leaf['ruleList'].length ; j++){
					// console.log(j);
					// console.log('leaf',leaf);
					if( leaf['ruleList'][i].action == leaf['ruleList'][j].action )
						leaf['anomalyInfo']['redundancy'].push({[i]:leaf['ruleList'][i],[j]:leaf['ruleList'][j]});
					
					else
						leaf['anomalyInfo']['shadowing'].push({[i]:leaf['ruleList'][i],[j]:leaf['ruleList'][j]});
				}				
			}				
		}
		else{
			console.log(leaf['ruleList'].length);
			leaf['anomalyInfo']['normal'].push(leaf['ruleList'][0]);	
		}
		
		//});
	});
	//console.log('leaf',leaf);
	console.log('portleaf',portleaf);
	return portleaf;

}
function checkPortAnomaly(portList,portBlock){
	// fill all the rule in the leafNode to routeObject
	//console.log('portList',portList);
	let startTime = process.hrtime();

	_.each(portList,function(leaf,leafCount){
		leaf['anomalyInfo'] = {
			'anomaly': false,
			'shadowing': [],
			'redundancy': [],
			'lost': [],
			'conflict': [],
			'consistent': [],

		};
			leaf['routeObject'] = portBlock['routeObject'];
		//console.log(leaf);
		if ( leaf['flag'] ) {
			_.each(leaf['ruleList'], function ( rule, ruleIdx ) {
				if ( rule['tcp_flags'].length === 0 ) {
					_.each(leaf['routeObject'], function ( extraRout,extraRoutkey ) {
						_.each(extraRout, function ( flagRoute, flagKey ) {
							_.each(flagRoute[rule.isExchange], function ( route, routeIdx ) {
								if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
									route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
								}
							});
						});
					});
				} else if ( rule['tcp_flags'].length === 1 ) {
					_.each(leaf['routeObject']['true'][rule.tcp_flags[0]][rule.isExchange], function ( route, routeIdx ) {
						if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
							route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
						}
					});
				} else {
					let tcp_flags;
					if ( rule['tcp_flags'][0] === 'ACK' ) {
						tcp_flags = `${rule['tcp_flags'][1]}+${rule['tcp_flags'][0]}`;
					} else {
						tcp_flags = `${rule['tcp_flags'][0]}+${rule['tcp_flags'][1]}`;
					}
					_.each(leaf['routeObject']['true'][tcp_flags][rule.isExchange], function ( route, routeIdx ) {
						if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
							route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
						}
					});
				}
			});
		} else {
			//console.log('flag',false);
			_.each(leaf['ruleList'], function ( rule, ruleIdx ) {
				//console.log('rule',rule,'ruleIdx',ruleIdx);
				_.each(leaf['routeObject'],function(extraRout,extraRoutkey){//ANY
					//console.log('rulextraRoute',extraRout,'extraRoutkey',extraRoutkey);
					_.each(extraRout, function ( flagRoute, flagKey ) {
						//console.log('flagRoute',flagRoute,flagRoute[rule.isExchange]);
						_.each(flagRoute[rule.isExchange], function ( route, routeIdx ) {
							// console.log('route',route,'ruleIdx',routeIdx);
							if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
								//console.log('route',route,'rule',rule);
								route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
								route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(ruleIdx);
							}
						});
					});
				});
				
			});
		}
		// check anomaly of the leafNode by routeObject
		// check shadowing, redundancy, lost and conflict
		let anomalyLocate;
		_.each(leaf['routeObject'], function ( extraRout,extraRoutkey ) {
			_.each(extraRout,function(flagRoute, flagKey ){
				_.each(flagRoute, function ( exchg, exchgKey ) {
					_.each(exchg, function ( route, routeIdx ) {
						route['sameAction'] = true;
						let hopKeyArray = Object.keys(route);

						_.each(route, function ( hop, hopKey ) {
							if ( (hopKey === 'sameAction') || (hopKey === 'action') ) return;
							hop['sameAction'] = true;
							//console.log('hop2',hop['ruleList'].length);
							if ( hop['ruleList'].length === 0 ) {
								hop['action'] = undefined;
								hop['sameAction'] = false;
								route['action'] = undefined;
								route['sameAction'] = false;
								leaf['anomalyInfo']['anomaly'] = true;
								leaf['anomalyInfo']['lost'].push([`${flagKey}-${exchgKey}-${routeIdx}-${hopKey}`]);
							} else {
								hop['action'] = hop['ruleList'][0]['action'];

								if ( hop['ruleList'].length > 1 ) {
									_.each(hop['ruleList'], function ( rule, ruleIdx ) {
										if ( ruleIdx !== 0 ) {
											anomalyLocate = [`${flagKey}-${exchgKey}-${routeIdx}-${hopKey}`];
											if ( rule['action'] !== hop['ruleList'][0]['action'] ) {
												// leaf['anomalyInfo']['anomaly'] = true;
												hop['sameAction'] = false;
												if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['shadowing']) ) {
													leaf['anomalyInfo']['shadowing'].push(anomalyLocate);
												}
											} else {
												if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['redundancy']) ) {
													leaf['anomalyInfo']['redundancy'].push(anomalyLocate);
												}
											}
										}
									});
									//console.log('anomalyLocate',anomalyLocate);
									// if ( hop['sameAction'] === true ) {
									// 	// leaf['anomalyInfo']['anomaly'] = true;
									// 	leaf['anomalyInfo']['redundancy'].push(`${flagKey}-${exchgKey}-${routeIdx}-${hopKey}`);
									// }
								}
							}

							let hopKeyIdx = hopKeyArray.indexOf(hopKey);
							if ( hopKeyIdx !== 0 ) {
								if ( hop['action'] !== route[hopKeyArray[hopKeyIdx-1]]['action'] ) {
									route['action'] = undefined;
									route['sameAction'] = false;
									anomalyLocate = [`${flagKey}-${exchgKey}-${routeIdx}`];
									if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
										leaf['anomalyInfo']['conflict'].push(anomalyLocate);
									}
									// leaf['anomalyInfo']['conflict'].push(`${flagKey}-${exchgKey}-${routeIdx}`);
								}
							}

						});	//	hop

						if ( route['sameAction'] === true ) {
							route['action'] = route[hopKeyArray[0]]['action'];
						}

					});	//	route
				});	//	exchg				
			});

		});	//	flagRoute
		// check consistent

		if ( leaf['flag'] ) {
			//console.log(456);
			let exchgKeyArray = ['false', 'true', 'false'];
			let flagKeyArray = Object.keys(leaf['routeObject']);
			_.each(leaf['routeObject']['true']['SYN'], function ( exchgS, exchgSKey ) {
				_.each(exchgS, function ( routeS, routeSIdx ) {
					if ( !routeS['sameAction'] ) return;
					let tarExchgSAKey = exchgKeyArray[exchgKeyArray.indexOf(exchgSKey) + 1];

					// check for SYN+ACK
					_.each(leaf['routeObject']['true']['SYN+ACK'][tarExchgSAKey], function ( routeSA, routeSAIdx ) {
						if ( !routeSA['sameAction'] ) return;
						if ( routeSA['action'] === routeS['action'] ) {
							// check for ACK
							_.each(leaf['routeObject']['true']['ACK']['false'], function ( routeAF, routeAFIdx ) {
								if ( !routeAF['sameAction'] )  return;
								_.each(leaf['routeObject']['true']['ACK']['true'], function ( routeAT, routeATIdx ) {
									if ( !routeAT['sameAction'] )  return;
									if ( routeAF['action'] === routeAT['action'] ) {
										if ( routeAT['action'] === routeS['action'] ) {
											// check for FIN series
											_.each(leaf['routeObject']['true']['FIN'], function ( exchgF, exchgFKey ) {
												_.each(exchgF, function ( routeF, routeFIdx ) {
													if ( !routeF['sameAction'] ) return;
													let tarExchgFAKey = exchgKeyArray[exchgKeyArray.indexOf(exchgFKey) + 1];
													
													_.each(leaf['routeObject']['true']['FIN+ACK'][tarExchgFAKey], function ( routeFA, routeFAIdx ) {
														if ( !routeFA['sameAction'] ) return;
														if ( routeFA['action'] === routeF['action'] ) {
															if ( routeFA['action'] === routeS['action'] ) {
																// check for RST
																_.each(leaf['routeObject']['true']['RST'], function ( exchgR, exchgRKey ) {
																	_.each(exchgR, function ( routeR, routeRIdx ) {
																		if ( !routeR['sameAction'] ) return;
																		if ( routeR['action'] === routeS['action'] ) {
																			let result = [];
																			result.push(`SYN-${exchgSKey}-${routeSIdx}`);
																			result.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																			result.push(`ACK-false-${routeAFIdx}`);
																			result.push(`ACK-true-${routeATIdx}`);
																			result.push(`FIN-${exchgFKey}-${routeFIdx}`);
																			result.push(`FIN+ACK-${tarExchgFAKey}-${routeFAIdx}`);
																			result.push(`RST-${exchgRKey}-${routeRIdx}`);
																			leaf['anomalyInfo']['consistent'].push(result);
																		} else {
																			anomalyLocate = []
																			anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
																			anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																			anomalyLocate.push(`ACK-false-${routeAFIdx}`);
																			anomalyLocate.push(`ACK-true-${routeATIdx}`);
																			anomalyLocate.push(`FIN-${exchgFKey}-${routeFIdx}`);
																			anomalyLocate.push(`FIN+ACK-${tarExchgFAKey}-${routeFAIdx}`);
																			anomalyLocate.push(`RST-${exchgRKey}-${routeRIdx}`);
																			if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																				leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																			}
																		}
																	});
																});

																_.each(leaf['routeObject']['RST']['false'], function ( routeRF, routeRFIdx ) {
																	if ( !routeRF['sameAction'] ) return;
																	_.each(leaf['routeObject']['RST']['true'], function ( routeRT, routeRTIdx ) {
																		if ( !routeRT['sameAction'] ) return;
																		if ( routeRF['action'] === routeRT['action'] ) {
																			if ( routeRF['action'] === routeS['action'] ) {
																				// add into consistent list
																				let result = [];
																				result.push(`SYN-${exchgSKey}-${routeSIdx}`);
																				result.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																				result.push(`ACK-false-${routeAFIdx}`);
																				result.push(`ACK-true-${routeATIdx}`);
																				result.push(`FIN-${exchgFKey}-${routeFIdx}`);
																				result.push(`FIN+ACK-${tarExchgFAKey}-${routeFAIdx}`);
																				result.push(`RST-false-${routeRFIdx}`);
																				result.push(`RST-true-${routeRTIdx}`);
																				leaf['anomalyInfo']['consistent'].push(result);
																			} else {
																				anomalyLocate = [];
																				anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
																				anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																				anomalyLocate.push(`ACK-false-${routeAFIdx}`);
																				anomalyLocate.push(`ACK-true-${routeATIdx}`);
																				anomalyLocate.push(`FIN-${exchgFKey}-${routeFIdx}`);
																				anomalyLocate.push(`FIN+ACK-${tarExchgFAKey}-${routeFAIdx}`);
																				anomalyLocate.push(`RST-false-${routeRFIdx}`);
																				anomalyLocate.push(`RST-true-${routeRTIdx}`);
																				if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																					leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																				}
																			}
																		} else {
																			anomalyLocate = [];
																			anomalyLocate.push(`RST-false-${routeRFIdx}`);
																			anomalyLocate.push(`RST-true-${routeRTIdx}`);
																			if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																				leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																			}
																		}
																	});
																});

															} else {
																anomalyLocate = [];
																anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
																anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																anomalyLocate.push(`ACK-false-${routeAFIdx}`);
																anomalyLocate.push(`ACK-true-${routeATIdx}`);
																anomalyLocate.push(`FIN-${exchgFKey}-${routeFIdx}`);
																anomalyLocate.push(`FIN+ACK-${tarExchgFAKey}-${routeFAIdx}`);
																if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																	leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																}
															}
														} else {
															anomalyLocate = [];
															anomalyLocate.push(`FIN-${exchgFKey}-${routeFIdx}`);
															anomalyLocate.push(`FIN+ACK-${tarExchgFAKey}-${routeFAIdx}`);
															if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																leaf['anomalyInfo']['conflict'].push(anomalyLocate);
															}
														}
													});

												});
											});


											_.each(leaf['routeObject']['FIN']['false'], function ( routeFF, routeFFIdx ) {
												if ( !routeFF['sameAction'] ) return;
												_.each(leaf['routeObject']['FIN']['true'], function ( routeFT, routeFTIdx ) {
													if ( !routeFT['sameAction'] ) return;
													if ( routeFF['action'] === routeFT['action'] ) {
														_.each(leaf['routeObject']['FIN+ACK']['false'], function ( routeFAF, routeFAFIdx ) {
															if ( !routeFAF['sameAction'] ) return;
															if ( routeFAF['action'] === routeFF['action'] ) {
																_.each(leaf['routeObject']['FIN+ACK']['true'], function ( routeFAT, routeFATIdx ) {
																	if ( !routeFAT['sameAction'] ) return;
																	if ( routeFAT['action'] === routeFAF['action'] ) {
																		if ( routeFAF['action'] === routeS['action'] ) {
																			// check for RST
																			// fix me
																			_.each(leaf['routeObject']['RST'], function ( exchgR, exchgRKey ) {
																				_.each(exchgR, function ( routeR, routeRIdx ) {
																					if ( !routeR['sameAction'] ) return;
																					if ( routeR['action'] === routeS['action'] ) {
																						let result = [];
																						result.push(`SYN-${exchgSKey}-${routeSIdx}`);
																						result.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																						result.push(`ACK-false-${routeAFIdx}`);
																						result.push(`ACK-true-${routeATIdx}`);
																						result.push(`FIN-false-${routeFFIdx}`);
																						result.push(`FIN-true-${routeFTIdx}`);
																						result.push(`FIN+ACK-false-${routeFAFIdx}`);
																						result.push(`FIN+ACK-true-${routeFATIdx}`);
																						result.push(`RST-${exchgRKey}-${routeRIdx}`);
																						leaf['anomalyInfo']['consistent'].push(result);
																					} else {
																						anomalyLocate = [];
																						anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
																						anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																						anomalyLocate.push(`ACK-false-${routeAFIdx}`);
																						anomalyLocate.push(`ACK-true-${routeATIdx}`);
																						anomalyLocate.push(`FIN-false-${routeFFIdx}`);
																						anomalyLocate.push(`FIN-true-${routeFTIdx}`);
																						anomalyLocate.push(`FIN+ACK-false-${routeFAFIdx}`);
																						anomalyLocate.push(`FIN+ACK-true-${routeFATIdx}`);
																						anomalyLocate.push(`RST-${exchgRKey}-${routeRIdx}`);
																						if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																							leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																						}
																					}
																				});
																			});

																			_.each(leaf['routeObject']['RST']['false'], function ( routeRF, routeRFIdx ) {
																				if ( !routeRF['sameAction'] ) return;
																				_.each(leaf['routeObject']['RST']['true'], function ( routeRT, routeRTIdx ) {
																					if ( !routeRT['sameAction'] ) return;

																					if ( routeRF['action'] === routeRT['action'] ) {
																						if ( routeRF['action'] === routeS['action'] ) {
																							// add into consistent list
																							let result = [];
																							result.push(`SYN-${exchgSKey}-${routeSIdx}`);
																							result.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																							result.push(`ACK-false-${routeAFIdx}`);
																							result.push(`ACK-true-${routeATIdx}`);
																							result.push(`FIN-false-${routeFFIdx}`);
																							result.push(`FIN-true-${routeFTIdx}`);
																							result.push(`FIN+ACK-false-${routeFAFIdx}`);
																							result.push(`FIN+ACK-true-${routeFATIdx}`);
																							result.push(`RST-false-${routeRFIdx}`);
																							result.push(`RST-true-${routeRTIdx}`);
																							leaf['anomalyInfo']['consistent'].push(result);
																						} else {
																							anomalyLocate = [];
																							anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
																							anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																							anomalyLocate.push(`ACK-false-${routeAFIdx}`);
																							anomalyLocate.push(`ACK-true-${routeATIdx}`);
																							anomalyLocate.push(`FIN-false-${routeFFIdx}`);
																							anomalyLocate.push(`FIN-true-${routeFTIdx}`);
																							anomalyLocate.push(`FIN+ACK-false-${routeFAFIdx}`);
																							anomalyLocate.push(`FIN+ACK-true-${routeFATIdx}`);
																							anomalyLocate.push(`RST-false-${routeRFIdx}`);
																							anomalyLocate.push(`RST-true-${routeRTIdx}`);
																							if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																								leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																							}
																						}
																					} else {
																						anomalyLocate = [];
																						anomalyLocate.push(`RST-false-${routeRFIdx}`);
																						anomalyLocate.push(`RST-true-${routeRTIdx}`);
																						if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																							leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																						}
																					}
																				});
																			});


																		} else {
																			anomalyLocate = [];
																			anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
																			anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
																			anomalyLocate.push(`ACK-false-${routeAFIdx}`);
																			anomalyLocate.push(`ACK-true-${routeATIdx}`);
																			anomalyLocate.push(`FIN-false-${routeFFIdx}`);
																			anomalyLocate.push(`FIN-true-${routeFTIdx}`);
																			anomalyLocate.push(`FIN+ACK-false-${routeFAFIdx}`);
																			anomalyLocate.push(`FIN+ACK-true-${routeFATIdx}`);
																			if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																				leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																			}
																		}
																	} else {
																		anomalyLocate = [];
																		anomalyLocate.push(`FIN-false-${routeFFIdx}`);
																		anomalyLocate.push(`FIN-true-${routeFTIdx}`);
																		anomalyLocate.push(`FIN+ACK-false-${routeFAFIdx}`);
																		anomalyLocate.push(`FIN+ACK-true-${routeFATIdx}`);
																		if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																			leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																		}
																	}
																});
															} else {
																anomalyLocate = [];
																anomalyLocate.push(`FIN-false-${routeFFIdx}`);
																anomalyLocate.push(`FIN-true-${routeFTIdx}`);
																anomalyLocate.push(`FIN+ACK-false-${routeFAFIdx}`);
																if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
																	leaf['anomalyInfo']['conflict'].push(anomalyLocate);
																}
															}
														});
													} else {
														anomalyLocate = [];
														anomalyLocate.push(`FIN-false-${routeFFIdx}`);
														anomalyLocate.push(`FIN-true-${routeFTIdx}`);
														if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
															leaf['anomalyInfo']['conflict'].push(anomalyLocate);
														}
													}

												});
											});


										} else {
											anomalyLocate = [];
											anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
											anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
											anomalyLocate.push(`ACK-false-${routeAFIdx}`);
											anomalyLocate.push(`ACK-true-${routeATIdx}`);
											if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
												leaf['anomalyInfo']['conflict'].push(anomalyLocate);
											}
										}
									} else {
										anomalyLocate = [];
										anomalyLocate.push(`ACK-false-${routeAFIdx}`);
										anomalyLocate.push(`ACK-true-${routeATIdx}`);
										if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
											leaf['anomalyInfo']['conflict'].push(anomalyLocate);
										}
									}
								});
							});

						} else {
							anomalyLocate = [];
							anomalyLocate.push(`SYN-${exchgSKey}-${routeSIdx}`);
							anomalyLocate.push(`SYN+ACK-${tarExchgSAKey}-${routeSAIdx}`);
							if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
								leaf['anomalyInfo']['conflict'].push(anomalyLocate);
							}
						}
					});			
				}); //	exchgS
			});
			// anomalyLocate = `ANY-false-${routeFIdx},ANY-true-${routeTIdx}`;
			// if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
			// 	leaf['anomalyInfo']['conflict'].push(anomalyLocate);
			// }

			if ( leaf['anomalyInfo']['consistent'].length === 0 ) {
				leaf['anomalyInfo']['anomaly'] = true;
			}
		} else {
			//console.log('leaf2',leaf['routeObject']);
			//console.log(123);
			_.each(leaf['routeObject']['false']['ANY']['false'], function ( routeF, routeFIdx ) {
				if ( routeF['sameAction'] ) {
					_.each(leaf['routeObject']['false']['ANY']['true'], function ( routeT, routeTIdx ) {
						if ( routeT['sameAction'] ) {
							if ( routeF['action'] === routeT['action'] ) {
								leaf['anomalyInfo']['consistent'].push([`ANY-false-${routeFIdx}`, `ANY-true-${routeTIdx}`]);
							} else {
								anomalyLocate = [`ANY-false-${routeFIdx}`, `ANY-true-${routeTIdx}`];
								if ( !checkElementIsExistInArray(anomalyLocate, leaf['anomalyInfo']['conflict']) ) {
									leaf['anomalyInfo']['conflict'].push(anomalyLocate);
								}
							}
						}
					});
				}
			});

			if ( leaf['anomalyInfo']['consistent'].length === 0 ) {
				leaf['anomalyInfo']['anomaly'] = true;
			}
		}
	});
	let createTime = process.hrtime(startTime);
	console.log(`anomaly: ` + (createTime[0] + createTime[1]/1e9));
}
	//console.log('portLeaf',node.nodeName,portLeaf);
function depictportResult (thisindex,portleaf) 
{	console.log('thisindex',thisindex);
	if ( $('#page-body').hasClass('hidden') ) $('#page-body').removeClass('hidden');
	$('#port-chart-tabs').empty();
	$('#port-tab-content').empty();
	
	let chartID = `chart-${thisindex}`;
	let $tab = `<li id="li-${thisindex}"><a data-toggle="tab" href="#tab-${thisindex}">block${thisindex}</a></li>`;
	// let $chart = `<div id="tab-${nodeName}" class="tab-pane fade"><div id="${chartID}" style="height:400px"></div></div>`;
	let $chart = `<div id="tab-${thisindex}" class="tab-pane fade">
					<div class="row"> 
						<div class="col-xs-12"> 
							<div id="${chartID}" style="height:400px"></div> 
						</div> 
					</div>
				</div>
				`;

	$($tab).appendTo('#port-chart-tabs');
	$($chart).appendTo('#port-tab-content');
	//Object.keys(portleaf).forEach(function ( leaf, leafCount ) {		
		// let curNode = myObject['aclObject'][nodeName];
		// if ( !myObject['aclObject'][nodeName].hasOwnProperty('ARARTree') ) {
		//  	showingNodeCount++;
		//  	return;
		//  }
	// _.each(portleaf,function(leaf, leafCount ){
	$(`#tab-${thisindex}`).addClass('in active');
	$(`#li-${thisindex}`).addClass('active');
	createHighcharts(chartID, portleaf);

	function createHighcharts ( chartID, dataList ) {
		let chart = {
			chart: { type: 'arearange', zoomType: 'xy'},
			title: { text: null },
			tooltip: { 
				followPointer: true,
				useHTML: true,
				headerFormat: `<div class="center" style="font-size: 14px; font-weight: bold">{series.name}</div></hr><div><table>`,
				footerFromat: '</table></div>',
				pointFormatter: function () {
					var str =	`<tr><td>Src:&#160;</td>\
									<td>${this.series.xData[0]}</td>\
									<td>&#160;~&#160;</td>\
									<td>${this.series.xData[1]}</td>\
								</tr>\
								<tr>\
									<td>Dest:&#160;</td>\
									<td>${(this.low)}</td>\
									<td>&#160;~&#160;</td>\
									<td>${(this.high)}</td>\
								</tr>`;
					
					return str;
				},
			},

			plotOptions: {
				series: {
					stickyTracking: false,
					trackByArea: true,
					showInLegend: false,
					fillOpacity: 0.5,
					lineWidth: 0.5,
					marker: { enabled: false, states: { hover: { enabled: false } } },
					cursor: 'pointer',
					//events: { click: createPortChart },
				}
			},
			xAxis: {
				title: "Source Address",
				labels: { formatter: function () { return this.value; } },
				floor: 0,
				ceiling: 65535,
			},

			yAxis: {
				title: "Destination Address",
				labels: { formatter: function () { return this.value; } },
				floor: 0,
				ceiling: 655535,
			}
		};
		chart.series = createSeries(dataList);
		Highcharts.chart(chartID, chart);
		
	}
	function createSeries ( dataList ) {
		let seriesList = [];
		//console.log(dataList);
		//console.log('createSeries',159);
		dataList.forEach(function ( data, dataCount ) {
			let series, xMin, xMax, yMin, yMax;
			// let src = new PortObject(data['listOrder'], data['src_port']);
			// let dst = new PortObject(data['listOrder'], data['dest_port']);
			xMin = data['min_src'];
			yMin = data['min_dst'];
			xMax = data['max_src'];
			yMax = data['max_dst'];

			series = { 
				name: `block ${dataCount}`, //red
				data: [{ x: xMin, low: yMin, high: yMax }, { x: xMax, low: yMin, high: yMax }],
			};

			if ( data['anomalyInfo']['normal'].length != 0) 
				{ series.color = '#90ed7d'; }
			else 
				{ series.color = '#f45b5b'; }

			seriesList.push(series);
		});
		return seriesList;
	}
}

function createPortChart ( portleaf ) {
	console.log(portleaf);
	// let nodeName = (event.point.series.chart.renderTo.id).split('-')[1];
	let block = portleaf[this.index];
	console.log(this.index, block);

	$.gritter.removeAll();
	//$(`#tab-${nodeName} div#block-content`).empty();
	$(`div#block-content`).empty();
	let $chart = fs.readFileSync(`${__dirname}/templates/port-information.html`, 'utf-8').toString();
	_.each(portleaf['ruleList'],function (leaf,leafCount){

	});

}

function putVector ( ruleList ) {
	//console.log(ruleList);
	var vector = [];
	var spaceCnt = -1;
	var maxSpace = 30; //30
	for ( var ruleCnt = 0; ruleCnt < ruleList.length; ruleCnt++ ) {
		if ( ruleCnt % maxSpace == 0 ) spaceCnt++;
		for ( var idxCnt = 0; idxCnt < 65535; idxCnt++ ) {//65536
			vector[idxCnt] = vector[idxCnt] || [];
			if ( ruleCnt % maxSpace != 0 ) {
				if ( ( idxCnt >= ruleList[ruleCnt]['min'] ) && ( idxCnt <= ruleList[ruleCnt]['max'] ) )
					vector[idxCnt][spaceCnt] = ( vector[idxCnt][spaceCnt] * 2 ) + 1;
				else 
					vector[idxCnt][spaceCnt] = vector[idxCnt][spaceCnt] * 2;
			} else {
				if ( ( idxCnt >= ruleList[ruleCnt]['min'] ) && ( idxCnt <= ruleList[ruleCnt]['max'] ) )
					vector[idxCnt].push(1);
				else
					vector[idxCnt].push(0);
			}
		}
	}
	return vector;
}

function portExtractor ( dataList ) {
	var srcList = [], dstList = [];
	dataList.forEach(function ( data, dataCount ) {
		srcList.push(new PortObject(data['listOrder'], data['src_port']));
		dstList.push(new PortObject(data['listOrder'], data['dest_port']));
	});
	return [srcList, dstList];
}

function merge (portVector){
	var mergedVector = [ [], [] ];
	//console.log('portVector',portVector);
	//console.log('portVector[0] length',portVector[0].length);

	for (var j = 0; j < mergedVector.length; j++) {
		for (var i = 0; i < (portVector[j].length - 1); i++) {
			//console.log(i, mergedVector[j]);
			if ( _.isEmpty(mergedVector[j]) ) 
				mergedVector[j].push({ 'min' : i, 'max' : i, 'data' : portVector[j][i] });
			if ( _.isEqual(portVector[j][i], portVector[j][i+1]) )
				mergedVector[j][mergedVector[j].length-1]['max'] = i + 1;
			else
				mergedVector[j].push({ 'min' : i + 1, 'max' : i + 1, 'data' : portVector[j][i+1] });
		}
	}
	//console.log('mergedVector:', mergedVector);
	return mergedVector;
}

function and(mergedVector){
	var andVector = [];
	let leafList = [];
	for(var i = 0 ; i < mergedVector[0].length ; i++){ //mergedVector[0]:Src
		andVector[i]=andVector[i]||[];	
		for(var j = 0 ; j < mergedVector[1].length ; j++){ //mergedVector[1]:dst
			andVector[i][j] = andVector[i][j] || {'min_src': mergedVector[0][i]['min'],'min_dst':mergedVector[1][j]['min'] ,
												  'max_src': mergedVector[0][i]['max'],'max_dst':mergedVector[1][j]['max'] ,
												  'data':[] ,'ruleList':[],'routeObject':[]};

			for(var z=0 ; z < mergedVector[0][i]['data'].length ; z++){
				//console.log('i',i,'j',j,'z',z);
				andVector[i][j]['data'][z] = mergedVector[0][i]['data'][z] & mergedVector[1][j]['data'][z];							
			}
			// console.log('andVector[i][j]',andVector[i][j]);	
		}
	}
	return andVector;
}
let portleaf = [];
function bitOrder(andVector,portRuleList,oriRuleList){

	
	for(var i = 0 ; i < andVector.length ; i++ ) {
		for (var j = 0; j < andVector[i].length ; j++) {
			var portRuleCnt = portRuleList.length - 1;

			for (var z = andVector[i][j]['data'].length - 1; z >= 0; z--) {
				var curData = andVector[i][j]['data'][z];

				if( z == (andVector[i][j]['data'].length - 1)){

					for(var k = portRuleCnt % 30 ; k >= 0 ; k--){
						if( (curData | 1) == curData ){
							//console.log('portRuleList',portRuleCnt,portRuleList[portRuleCnt]);
							andVector[i][j]['ruleList'].push(oriRuleList[portRuleList[portRuleCnt]['listOrder']]);
						}
						curData >>= 1;
						portRuleCnt--;
					}

				}else{
					for(var k = 30 ; k > 0 ; k--){
						if( (curData | 1) == curData ){
							//console.log('portRuleList',portRuleCnt,portRuleList[portRuleCnt]);
							andVector[i][j]['ruleList'].push(oriRuleList[portRuleList[portRuleCnt]['listOrder']]);
						}
						curData >>= 1;
						portRuleCnt--;
					}
				}		
			}
		}
	}
	//console.log('andVector',andVector);
	for(var i = 0 ; i < andVector.length ; i++ ) {
		for (var j = 0; j < andVector[i].length ; j++) {
			if( andVector[i][j]['ruleList'].length > 0 ){
				andVector[i][j]['flag'] = false;
				for(var z=0 ; z < andVector[i][j]['ruleList'].length ; z++){
					if (andVector[i][j]['ruleList'][z]['tcp_flags'].length > 0) {
						andVector[i][j]['flag'] = true;
					}
				}
				portleaf.push(andVector[i][j]);
			}
		}
	}
	//console.log('portleaf',portleaf);
	return portleaf;
}

function bitcount ( n ) {
	//console.log('n',n);
	var count = 0;
	// var n;
	while( n ) {
		count++;
		n &= ( n - 1);
	}
	return count;
}

function PortList ( listOrder, min_port,max_port) {
	this.listOrder = listOrder;
	this.min_port = min_port;
	this.max_port = max_port;
}

module.exports = portDiagnosis;
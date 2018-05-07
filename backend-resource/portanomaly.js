function checkPortAnomaly ( leafList ) {

	leafList['leafList'].forEach(function ( leaf, leafCount ) {
		leaf['routeObject'] = createRouteObject(leaf);
		leaf['anomalyInfo'] = {
			'anomaly': false,
			'shadowing': [],
			'redundancy': [],
			'lost': [],
			'conflict': [],
			'consistent': []
		};
		//console.log('leaf',leaf);
		// if ( leafCount === 0 ) console.log(leaf)

		// if it is not interFirewall, delete all the other interface information
		if ( node.nodeName !== 'interFirewall' ) {
			_.each(leaf['routeObject'], function ( flagRoute, flagKey ) {
				_.each(flagRoute, function ( exchg, exchgKey ) {
					_.each(exchg, function ( route, routeIdx ) {
						_.each(route, function ( hop, hopKey ) {
							if ( !_.isEqual(hopKey.split('_')[0], node.nodeName) ) {
								delete route[hopKey];
							}
						});
						if ( _.isEmpty(exchg[routeIdx]) ) { exchg[routeIdx] = undefined }
					});
					flagRoute[exchgKey] = _.compact(flagRoute[exchgKey]);
				});
			});
		}

		// fill all the rule in the leafNode to routeObject
		if ( leaf['flag'] ) {
			_.each(leaf['ruleList'], function ( rule, ruleIdx ) {
				if ( rule['tcp_flags'].length === 0 ) {
					_.each(leaf['routeObject'], function ( flagRoute, flagKey ) {
						_.each(flagRoute[rule.isExchange], function ( route, routeIdx ) {
							if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
								route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
							}
						});
					});
				} else if ( rule['tcp_flags'].length === 1 ) {
					_.each(leaf['routeObject'][rule.tcp_flags[0]][rule.isExchange], function ( route, routeIdx ) {
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
					_.each(leaf['routeObject'][tcp_flags][rule.isExchange], function ( route, routeIdx ) {
						if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
							route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
						}
					});
				}
			});
		} else {
			_.each(leaf['ruleList'], function ( rule, ruleIdx ) {
				_.each(leaf['routeObject'], function ( flagRoute, flagKey ) {
					_.each(flagRoute[rule.isExchange], function ( route, routeIdx ) {
						if ( route.hasOwnProperty(`${rule.nodeName}_${rule.interface}_${rule.in_out}`) ) {
							route[`${rule.nodeName}_${rule.interface}_${rule.in_out}`]['ruleList'].push(rule);
						}
					});
				});
			});
		}

		// check anomaly of the leafNode by routeObject
		// check shadowing, redundancy, lost and conflict
		let anomalyLocate;
		_.each(leaf['routeObject'], function ( flagRoute, flagKey ) {
			_.each(flagRoute, function ( exchg, exchgKey ) {
				_.each(exchg, function ( route, routeIdx ) {
					route['sameAction'] = true;
					let hopKeyArray = Object.keys(route);

					_.each(route, function ( hop, hopKey ) {
						if ( (hopKey === 'sameAction') || (hopKey === 'action') ) return;
						hop['sameAction'] = true;

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
		});	//	flagRoute
		// check consistent
		if ( leaf['flag'] ) {
			let exchgKeyArray = ['false', 'true', 'false'];
			let flagKeyArray = Object.keys(leaf['routeObject']);
			_.each(leaf['routeObject']['SYN'], function ( exchgS, exchgSKey ) {
				_.each(exchgS, function ( routeS, routeSIdx ) {
					if ( !routeS['sameAction'] ) return;
					let tarExchgSAKey = exchgKeyArray[exchgKeyArray.indexOf(exchgSKey) + 1];

					// check for SYN+ACK
					_.each(leaf['routeObject']['SYN+ACK'][tarExchgSAKey], function ( routeSA, routeSAIdx ) {
						if ( !routeSA['sameAction'] ) return;
						if ( routeSA['action'] === routeS['action'] ) {
							// check for ACK
							_.each(leaf['routeObject']['ACK']['false'], function ( routeAF, routeAFIdx ) {
								if ( !routeAF['sameAction'] )  return;
								_.each(leaf['routeObject']['ACK']['true'], function ( routeAT, routeATIdx ) {
									if ( !routeAT['sameAction'] )  return;
									if ( routeAF['action'] === routeAT['action'] ) {
										if ( routeAT['action'] === routeS['action'] ) {
											// check for FIN series
											_.each(leaf['routeObject']['FIN'], function ( exchgF, exchgFKey ) {
												_.each(exchgF, function ( routeF, routeFIdx ) {
													if ( !routeF['sameAction'] ) return;
													let tarExchgFAKey = exchgKeyArray[exchgKeyArray.indexOf(exchgFKey) + 1];
													
													_.each(leaf['routeObject']['FIN+ACK'][tarExchgFAKey], function ( routeFA, routeFAIdx ) {
														if ( !routeFA['sameAction'] ) return;
														if ( routeFA['action'] === routeF['action'] ) {
															if ( routeFA['action'] === routeS['action'] ) {
																// check for RST
																_.each(leaf['routeObject']['RST'], function ( exchgR, exchgRKey ) {
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
			_.each(leaf['routeObject']['ANY']['false'], function ( routeF, routeFIdx ) {
				if ( routeF['sameAction'] ) {
					_.each(leaf['routeObject']['ANY']['true'], function ( routeT, routeTIdx ) {
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
}

function createRouteObject ( leafList ) {
	//console.log('node',node);
	let routeObject;
	if ( leafList['ruleList'] ) { //node['flag'],True & False mean??
		routeObject = {
			'SYN': undefined,
			'SYN+ACK': undefined,
			'ACK': undefined,
			'FIN': undefined,
			'FIN+ACK': undefined,
			'RST': undefined,
		};
	} else {
		routeObject = { 'ANY': undefined };
	}

	_.each(routeObject, function ( flagRoute, flagKey ) {
		routeObject[flagKey] = createRouteList(node);
	});
	//console.log(routeObject);
	return routeObject;
}

function createRouteList ( leafList ) {
	let flagRoute = { false: [], true: [] };
	_.each(myObject.topoPath.routeTree, function ( from, fromKey ) {
		if ( checkIsSubnet((node.parameter.rsvSrc | node.parameter.baseSrc) >>> 0, myObject.topoPath.nodeArray[fromKey].address) ) {
			_.each(from, function ( to, toKey ) {
				if ( checkIsSubnet((node.parameter.rsvDest | node.parameter.baseDest) >>> 0, myObject.topoPath.nodeArray[toKey].address) ) {
					_.each(to, function ( path ) {
						let route = {};
						_.each(path, function ( hop, hopIdx ) {
							if ( (hopIdx === 0) || (hopIdx === (path.length - 1)) ) return;
							let fw = hop.nodeName;
							let eth = `eth${hop.interface}`;
							let io = hop.in_out;
							route[`${fw}_${eth}_${io}`] = route[`${fw}_${eth}_${io}`] || { ruleList: [] };
						});
						if ( !checkElementIsExistInArray(route, flagRoute['false']) ) {
							flagRoute['false'].push(route);
						}
					});
				}
			});
		} else if ( checkIsSubnet((node.parameter.rsvDest | node.parameter.baseDest) >>> 0, myObject.topoPath.nodeArray[fromKey].address) ) {
			_.each(from, function ( to, toKey ) {
				if ( checkIsSubnet((node.parameter.rsvSrc | node.parameter.baseSrc) >>> 0, myObject.topoPath.nodeArray[toKey].address) ) {
					_.each(to, function ( path ) {
						let route = {};
						_.each(path, function ( hop, hopIdx ) {
							if ( (hopIdx === 0) || (hopIdx === (path.length - 1)) ) return;
							let fw = hop.nodeName;
							let eth = `eth${hop.interface}`;
							let io = hop.in_out;
							route[`${fw}_${eth}_${io}`] = route[`${fw}_${eth}_${io}`] || { ruleList: [] };
						});
						if ( !checkElementIsExistInArray(route, flagRoute['true']) ) {
							flagRoute['true'].push(route);
						}
					});
				}
			});
		}
	});
	return flagRoute;
}

function checkIsSubnet ( ipAddr, nwAddr ) {
	let nw_ip, nw_mask, nw_min_ip, nw_max_ip;
	[nw_ip, nw_mask] = nwAddr.split('/');
	nw_ip = ipConvertor(nw_ip);
	nw_mask = parseInt(nw_mask);
	nw_min_ip = nw_ip;
	nw_max_ip = nw_min_ip | (((1 << (32 - nw_mask)) - 1) >>> 0);

	if ( (ipAddr >= nw_min_ip) && (ipAddr <= nw_max_ip) ) { return true; }
	return false;
}

function InterTree ( ruleList ) { this.nodeName = 'interFirewall'; this.ruleList = ruleList; this.ARARTree = undefined; }

/*	[myThesisObject Constructor]
 *	If it's a new project, there will be 'save-as' new file.
 *	If it's a object have been loaded or saved, there will be 'update' file.
 */
function myThesisObject ( item=null ) {
	if ( item === null) {
		this.filepath = null;
		this.nodeDataArray = [];
		this.linkDataArray = [];
		this.aclObject = {};
		this.isInspect = false;
	} else {
		this.filepath = item.filepath;
		this.nodeDataArray = item.nodeDataArray;
		this.linkDataArray = item.linkDataArray;
		this.aclObject = item.aclObject;
		this.isInspect = item.isInspect;
	}

	this.showObject = function ( mode=false ) {
		if ( mode )
			console.log(util.inspect( this, { showHidden: false, depth:null } ));
		else
			console.log(this);
	}
	this.start = function () {
		topoUI.init(this);
	}
	this.update = function () {
		topoUI.update(this);
		if ( this.isInspect ) depictResult();
	}

	
}
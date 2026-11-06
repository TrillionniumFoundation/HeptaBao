function executeComparison(input, compare) {
 const pairs = Object.fromEntries(Object.entries(input.rawReports).map(([role, routes]) => [role, Object.fromEntries(Object.entries(routes).map(([route, raw]) => [route, JSON.parse(raw)]))]));
 return compare(pairs, input.approvedModels);
}

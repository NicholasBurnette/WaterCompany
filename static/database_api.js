function getData(company, endpoint='../api/audits/data?company=') {
    let requestURL = endpoint + company;
    let request = new XMLHttpRequest();
    request.open('GET', requestURL, false);
    // request.responseType = 'json';
    request.send();
    return JSON.parse(request.response)
    // request.onload = function () {
    //    New way for if async
    // }
}
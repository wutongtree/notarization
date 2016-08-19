function checkSign(){
    var r = confirm("是否要继续签名啊?");
    return r;
};

var openFile = function(event) {
    var input = event.target;

    var reader = new FileReader();
    reader.onloadend = function(){
        var arrayBuffer = reader.result;

        var output = document.getElementsByName("filehash")[0];
        output.setAttribute("value", hex_md5(arrayBuffer));

        console.log(arrayBuffer.byteLength);
        console.log(hex_md5(arrayBuffer));
    };
    reader.readAsBinaryString(input.files[0]);
};
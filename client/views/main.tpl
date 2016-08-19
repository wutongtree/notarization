{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<div class="container">
    <h3>您所有的签名如下:</h3>
    <br>

    <form class="form-horizontal">
        {{range .Signatures.Signatures}}
        <ul class='grey rounded-box'>
            <li>
                <tr><b>文件名字: </b>{{.FileName}}</tr><br>
                <tr><b>文件摘要: </b>{{.FileHash}}</tr><br>
                <tr><b>文件签名: </b>{{.FileSignature}}</tr><br>
                <tr><b>签名时间: </b>{{.Timestamp}}</tr><br>
            </li>
        </ul>
        {{end}}
    </form>
</div>
{{end}}
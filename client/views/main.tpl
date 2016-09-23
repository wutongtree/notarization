{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<div class="Main">
    <h1 class="ttl withIco">您所有的签名如下:</h1>

    <ul class="List">
        {{range .Signatures.Signatures}}
        <li class="info">
            <p csstext="文件名字" class="t1">
              <em>{{.FileName}}</em></p>
            <p csstext="文件择要" class="t1">{{.FileHash}}</p>
            <p csstext="文件签名" class="t1">{{.FileSignature}}</p>
            <p csstext="签名时间" class="t1">{{.Timestamp}}</p>
        </li>
       {{end}}
    </ul>

    {{template "page.tpl" .}}
</div>
{{end}}
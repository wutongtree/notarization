{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<script src="/static/js/md5.js"></script>
<script src="/static/js/notarization.js"></script>
<div class="Main">
    <h1 class="ttl">请上传要签名的文件：</h1>
    
    <form id="signform" action="/sign" method="post" class="form" novalidate="novalidate" enctype="multipart/form-data"  onSubmit="return checkSign()">
        <div class="frmCol">
            <div class="frm">
                <em>文件摘要: </em>
                <input type="text" class="txt large" name="filehash" id="filehash" readonly required>
            </div>
        </div>

        <div class="frmCol">
            <div class="frm">
                <em>签名文件: </em>
                <input type="file" class="txt large" name="fileup" id="fileup" onchange="openFile(event)" required>
            </div>
        </div>
        
        <div class="frmCol">
            <div class="frm btns">
                  <button type="submit" class="btn btn_primary large">文件签名</button>
            </div>
        </div>

        {{if .IsSigned}}
            {{if .Success}}
                <div class="msg ok">
                    <div class="info">
                        <i class="ico"></i>
                        {{.Signstatus}}
                    </div>
                    <div class="desc">
                        <p csstext="文件名称" class="t1">
                            <em>{{.FileName}}</em>
                        </p>
                        <p csstext="文件签名" class="t1">{{.FileSignature}}</p>
                    </div>
                </div>
            {{else}}
                <div class="msg err">
                    <div class="info">
                        <i class="ico"></i>
                        {{.Signstatus}}
                    </div>
                </div>
            {{end}}
<!--
            <div class="frmCol">
                <div class="frm">
                    <em>签名结果: </em>
                    <label class="frm">{{.Signstatus}}</label>
                </div>
            </div>

            <div class="frmCol">
                <div class="frm">
                    <em>文件名称: </label>
                    <label class="frm">{{.FileName}}</label>
                </div>
            </div>

            <div class="frmCol">
                <div class="frm">
                    <em>文件签名: </label>
                    <label class="frm">{{.FileSignature}}</label>
                </div>
            </div>-->
        {{end}}
    </form>
</div>
{{end}}


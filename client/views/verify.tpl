{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<script src="/static/js/md5.js"></script>
<script src="/static/js/notarization.js"></script>
<div class="Main">
    <h1 class="ttl">请输入要验证的文件签名信息：</h1>
    
    <form action="/verify" method="post" novalidate="novalidate" class="form" enctype="multipart/form-data">
        <div class="frmCol">
            <div class="frm">
                <em>签名者: </em>
                <input type="text" class="txt large" name="signer" required>
            </div>
        </div>

        <div class="frmCol">
            <div class="frm">
                <em>文件签名: </em>
                <input type="text" class="txt large" name="filesignature" required>
            </div>
        </div>

        <div class="frmCol">
            <div class="frm">
                <em>文件摘要: </em>
                <input type="textarea" class="txt large" name="filehash" name="filehash" readonly required>
            </div>
        </div>

        <div class="frmCol">
            <div class="frm">
                <em>签名文件: </em>
                <input type="file" class="txt large" name="fileup" onchange="openFile(event)" required>
            </div>
        </div>
        
        <div class="frmCol">
            <div class="frm btns">
                <input type="submit" value="签名验证" class="btn btn_primary large"/> 
            </div>
        </div>

        {{if .IsSigned}}
           <!--<em>{{.Signstatus}}</em>-->
           {{if .Success}}
                <div class="msg ok">
                    <div class="info">
                        <i class="ico"></i>
                        {{.Signstatus}}
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
        {{end}}
    </form>
</div>
{{end}}


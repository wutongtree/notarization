{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<script src="/static/js/md5.js"></script>
<script src="/static/js/notarization.js"></script>
<div class="container">
    <h3>请输入要验证的文件签名信息：</h3>
    <br>
    <form action="/verify" method="post" class="form-horizontal" enctype="multipart/form-data">
        <div class="form-group">
            <label class="col-md-3 control-label">签名者: </label>
            <div class="col-md-5" class="form-horizontal">
                  <input type="text" class="form-control" name="signer" required>
            </div>
        </div>

        <div class="form-group">
            <label class="col-md-3 control-label">文件签名: </label>
            <div class="col-md-5">
                <input type="text" class="form-control" name="filesignature" required>
            </div>
        </div>

        <div class="form-group">
            <label class="col-md-3 control-label">文件摘要: </label>
            <div class="col-md-5" class="form-horizontal">
                  <input type="textarea" class="form-control" name="filehash" name="filehash" readonly required>
            </div>
        </div>

        <div class="form-group">
            <label class="col-md-3 control-label">签名文件: </label>
            <div class="col-md-5" class="form-horizontal">
                  <input type="file" class="form-control" name="fileup" onchange="openFile(event)" required>
                  <input type="submit" value="文件上传" class="btn btn-info col-sm-offset-8"/>  
            </div>
        </div>

        {{if .IsSigned}}
            <label class="">{{.Signstatus}}</label>
        {{end}}
    </form>
</div>
{{end}}


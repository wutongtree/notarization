{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<script src="/static/js/md5.js"></script>
<script src="/static/js/notarization.js"></script>
<div class="container">
    <h3>请上传要签名的文件：</h3>
    <br>
    <form id="signform" action="/sign" method="post" class="form-horizontal" enctype="multipart/form-data"  onSubmit="return checkSign()">
        <div class="form-group">
            <label class="col-md-3 control-label">文件摘要: </label>
            <div class="col-md-5" class="form-horizontal">
                  <input type="textarea" class="form-control" name="filehash" id="filehash" readonly required>
            </div>
        </div>

        <div class="form-group">
            <label class="col-md-3 control-label">签名文件: </label>
            <div class="col-md-5" class="form-horizontal">
                  <input type="file" class="form-control" name="fileup" id="fileup" onchange="openFile(event)" required>
                  <input type="submit" value="文件上传" class="btn btn-info"/>  
            </div>
        </div>

        {{if .IsSigned}}
            <div class="form-group">
                <label class="col-md-3 control-label">签名结果: </label>
                <label class="control-label">{{.Signstatus}}</label>
            </div>

            <div class="form-group">
                <label class="col-md-3 control-label">文件名称: </label>
                <label class="control-label">{{.FileName}}</label>
            </div>

            <div class="form-group">
                <label class="col-md-3 control-label">文件签名: </label>
                <label class="control-label">{{.FileSignature}}</label>
            </div>
        {{end}}
    </form>
</div>
{{end}}


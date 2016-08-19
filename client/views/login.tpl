{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<div class="container" style="width: 500px;">
    <h3>请输入用户名和密码登录系统</h3>
    <br>
    <form action="/login" method="post" class="form-horizontal">
        <div class="form-group">
            <label class="col-md-3 control-label">用户名: </label>
            <div class="col-md-5">
                  <input type="text" class="form-control" name="uname" required>
            </div>
        </div>

        <div class="form-group">
            <label class="col-md-3 control-label">密码: </label>
            <div class="col-md-5">
                  <input type="password" class="form-control" name="upass" required>
            </div>
        </div>

        <div class="form-group">
            <div class="col-sm-offset-6 col-sm-10">
                <button type="submit" class="btn btn-info">{{i18n .Lang "login"}}</button>
            </div>
        </div>
    </form>
</div>
{{end}}


{{template "base/base.html" .}}
{{define "head"}}
{{end}}
{{define "body"}}
<div class="Main">
    <h1 class="ttl">请输入用户名和密码登录系统</h1>
    
    <form action="/login" method="post" class="form">
        <div class="frmCol">
            <div class="frm">
                <em>用户名: </em>
                <input type="text" class="txt large" name="uname" required>
            </div>
        </div>

        <div class="frmCol">
            <div class="frm">
                <em>密码: </em>
                <input type="password" class="txt large" name="upass" required>
            </div>
        </div>

        <div class="frmCol">
            <div class="frm btns">
                <button type="submit" class="btn btn_primary large">登录</button>
            </div>
        </div>
    </form>
</div>
{{end}}

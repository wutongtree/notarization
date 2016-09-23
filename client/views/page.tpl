{{if .paginator.HasPages}}
  <div class="pager">
    {{if .paginator.HasPrev}}
      <a href="{{.paginator.PageLinkPrev}}" class="pg prev">
        <i title="上一页" class="iF iF-arrowL"></i>
      </a>
    {{else}}
      <a href="#" disabled="disabled" class="pg prev">
        <i title="上一页" class="iF iF-arrowL"></i>
      </a>
    {{end}}

    {{range $index, $page := .paginator.Pages}}
      <a href="{{$.paginator.PageLink $page}}" class="pg {{if $.paginator.IsActive .}}cur{{end}}">{{$page}}</a>
    {{end}}

    {{if .paginator.HasNext}}
      <a href="{{.paginator.PageLinkNext}}" class="pg next">
        <i title="下一页" class="iF iF-arrowR"></i>
      </a>
    {{else}}
      <a href="#" disabled="disabled" class="pg next">
        <i title="下一页" class="iF iF-arrowR"></i>
      </a>
    {{end}}
  </div>
{{end}}
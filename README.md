revel-csrf
==========

`revel-csrf` implements Cross-Site Request Forgery (CSRF) attacks
prevention for the [Revel framework](https://github.com/revel/revel).

Code is based on the `nosurf` package implemented by
[Justinas Stankevičius](https://github.com/justinas/nosurf).

Code is a fork of [https://github.com/cbonello/revel-csrf](https://github.com/cbonello/revel-csrf) with improvements and latest changes to Revel

## Installation

    go get github.com/anikitenko/revel-csrf

A demo application is provided in the samples directory. To launch it:

    revel run github.com/anikitenko/revel-csrf/samples/demo

## Configuration options

Revel-csrf supports following configuration options in `app.conf`:

* `csrf.ajax`
A boolean value that indicates whether or not `revel-csrf` should support the injection and verification of CSRF tokens for XMLHttpRequests. Default value is `false`.

* `csrf.token.length`
An integer value that defines the number of characters that should be found within CSRF tokens. Token length should be in [32..512] and default value is 32 characters.

* `csrf.forbidden`
A string value which indicates redirect URL. Default is "" which mean that on error you'll be redirected to default 403 page

* `csrf.errNoReferer`
A string value which indicates message on error when no referer in request. Default is "" which mean
`A secure request contained no Referer or its value was malformed!`

* `csrf.errBadReferer`
A string value which indicates message on same-origin policy failure. Defailt is "" which mean
`Same-origin policy failure!`

* `csrf.errBadToken`
A string value which indicates message on csrf tokens mismatch. Default is "" which mean
`Tokens mismatch!`

## Operating instructions

Simply call the Filter() filter in `app/init.go`.  

    package app

    import (
        "github.com/anikitenko/revel-csrf"
        "github.com/revel/revel"
    )

    func init() {
	    // Filters is the default set of global filters.
	    revel.Filters = []revel.Filter{
		    revel.PanicFilter,             // Recover from panics and display an error page instead.
		    revel.RouterFilter,            // Use the routing table to select the right Action
		    revel.FilterConfiguringFilter, // A hook for adding or removing per-Action filters.
		    revel.ParamsFilter,            // Parse parameters into Controller.Params.
		    revel.SessionFilter,           // Restore and write the session cookie.
		    revel.FlashFilter,             // Restore and write the flash cookie.
		    csrf.Filter,                   // CSRF prevention.
		    revel.ValidationFilter,        // Restore kept validation errors and save new ones from cookie.
		    revel.I18nFilter,              // Resolve the requested language
		    revel.InterceptorFilter,       // Run interceptors around the action.
		    revel.ActionInvoker,           // Invoke the action.
	    }
    }

Insert a hidden input field named `csrf_token` in your forms.

    <form action="/Hello" method="POST">
        <input type="text" name="name" />
        <input type="hidden" name="csrf_token" value="{{ .csrf_token }}" />
        <button type="submit">Send</button>
    </form>

Javascript-code sample to perform AJAX calls with jQuery 1.5 and newer. 

    function csrfSafeMethod(method) {
        // HTTP methods that do not require CSRF protection.
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        crossDomain: false,
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type)) {
                xhr.setRequestHeader("X-CSRFToken", {{ .csrf_token }});
            }
        }
    });

	$("#AJAXForm").submit(function(event){
		event.preventDefault();
	    $.ajax({
	        type: "POST",
	        url: "/Hello",
	        data: {
	            name: $("#AJAXFormName").val()
	        },
	        success: function(data) {
	            // Switch to HTML code returned by server on success.
	            jQuery("body").html(data);
	        },
	        error: function(jqXHR, status, errorThrown) {
	            alert(jqXHR.statusText);
	        },
	    });
	});

`csrf.GenerateNewToken(c)` is used to generate new token and set it in session

`csrf.ExemptedFullPath()` is used to extempt exact URL path from CSRF checks.

`csrf.ExemptedFullPaths()` is the same as the previous one but accepts multiple arguments as URL path strings

`csrf.ExtemptedAction()` is used to extempt exact action from CSRF checks e.g. `Controller.Action`

`csrf.ExtemptedActions()` does the same as previous one but accepts multiple controllers

`csrf.ExemptedGlob()` is used to extempt URL path by matching it using `path.Match` func. Argument to `ExemptedGlob()` func is `pattern string`

`csrf.ExemptedGlobs()` does the same as previous one but accepts multiple patterns

## TODO

* Test cases.

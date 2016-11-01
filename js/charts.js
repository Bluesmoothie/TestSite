function index_to_shortname( index ){
    return ["xss_tag","xss_event","xss","no_sql_injection_differential","unencrypted_password_forms","common_directories","private_ip","x_frame_options","password_autocomplete","interesting_responses","http_only_cookies"][index];
}

function index_to_severity( index ){
    return {"xss_tag":"high","xss_event":"high","xss":"high","no_sql_injection_differential":"high","unencrypted_password_forms":"medium","common_directories":"medium","private_ip":"low","x_frame_options":"low","password_autocomplete":"low","interesting_responses":"informational","http_only_cookies":"informational"}[index_to_shortname(index)];
}

function renderCharts() {
    if( window.renderedCharts )
    window.renderedCharts = true;

    c3.generate({
        bindto: '#chart-issues',
        data: {
            columns: [
                ["Trusted",1,1,1,1,1,1,1,2,1,10,1],
                ["Untrusted",0,0,0,0,0,0,0,0,0,0,0],
                ["Severity",4,4,4,4,3,3,2,2,2,1,1]
            ],
            axes: {
                Severity: 'y2'
            },
            type: 'bar',
            groups: [
                ['Trusted', 'Untrusted']
            ],
            types: {
                Severity: 'line'
            },
            onclick: function (d) {
                var location;

                if( d.name.toLowerCase() == 'severity' ) {
                    location = 'summary/issues/trusted/severity/' + index_to_severity(d.x);
                } else {
                    location = 'summary/issues/' + d.name.toLowerCase() + '/severity/' +
                        index_to_severity(d.x) + '/' + index_to_shortname(d.x);
                }

                goToLocation( location );
            }
        },
        regions: [{"class":"severity-high","start":0,"end":3},{"class":"severity-medium","start":4,"end":5},{"class":"severity-low","start":6,"end":8},{"class":"severity-informational","start":9}],
        axis: {
            x: {
                type: 'category',
                categories: ["Cross-Site Scripting (XSS) in HTML tag","Cross-Site Scripting (XSS) in event tag of HTML element","Cross-Site Scripting (XSS)","Blind NoSQL Injection (differential analysis)","Unencrypted password form","Common directory","Private IP address disclosure","Missing 'X-Frame-Options' header","Password field with auto-complete","Interesting response","HttpOnly cookie"],
                tick: {
                    rotate: 15
                }
            },
            y: {
                label: {
                    text: 'Amount of logged issues',
                    position: 'outer-center'
                }
            },
            y2: {
                label: {
                    text: 'Severity',
                    position: 'outer-center'
                },
                show: true,
                type: 'category',
                categories: [1, 2, 3, 4],
                tick: {
                    format: function (d) {
                        return ["Informational","Low","Medium","High"][d - 1]
                    }
                }
            }
        },
        padding: {
            bottom: 40
        },
        color: {
            pattern: [ '#1f77b4', '#d62728', '#ff7f0e' ]
        }
    });

    c3.generate({
        bindto: '#chart-trust',
        data: {
            type: 'pie',
            columns: [["Trusted",21],["Untrusted",0]]
        },
        pie: {
            onclick: function (d) { goToLocation( 'summary/issues/' + d.id.toLowerCase() ) }
        },
        color: {
            pattern: [ '#1f77b4', '#d62728' ]
        }
    });

    c3.generate({
        bindto: '#chart-elements',
        data: {
            type: 'pie',
            columns: [["form",2],["link",3],["cookie",2],["body",1],["server",13]]
        }
    });

    c3.generate({
        bindto: '#chart-severities',
        data: {
            type: 'pie',
            columns: [["high",4],["medium",2],["low",4],["informational",11]]
        },
        color: {
            pattern: [ '#d62728', '#ff7f0e', '#ffbb78', '#1f77b4' ]
        },
        pie: {
            onclick: function (d) {
                goToLocation( 'summary/issues/trusted/severity/' + d.id );
            }
        }
    });

}

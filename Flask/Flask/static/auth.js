var keycloak = Keycloak("{{url_for('static', filename='keycloak.json')}}");
keycloak.init().success(function(authenticated) {
    console.log(authenticated ? 'authenticated' : 'not authenticated');
}).error(function() {
    console.log('failed to initialize');
});
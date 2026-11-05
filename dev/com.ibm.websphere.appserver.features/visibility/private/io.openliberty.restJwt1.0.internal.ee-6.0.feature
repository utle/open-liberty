-include= ~${workspace}/cnf/resources/bnd/feature.props
symbolicName=io.openliberty.restJwt1.0.internal.ee-6.0
singleton=true
WLP-DisableAllFeatures-OnConflict: false
visibility=private
-features=\
  io.openliberty.servlet.api-3.0; ibm.tolerates:="3.1, 4.0"
-bundles=\
  io.openliberty.security.rest.jwt
kind=ga
edition=core
WLP-Activation-Type: parallel

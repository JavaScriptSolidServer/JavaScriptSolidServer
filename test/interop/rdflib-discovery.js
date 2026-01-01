const rdf = require('rdflib');

const webId = 'https://melvincarvalho.com/#me';

const store = rdf.graph();
const fetcher = rdf.fetcher(store);

console.log('Testing rdflib fetch of WebID:', webId);

fetcher.load(webId, { force: true })
  .then(response => {
    console.log('\n=== Response ===');
    console.log('Status:', response.status);
    
    const providerTerm = rdf.namedNode('http://www.w3.org/ns/solid/terms#oidcIssuer');
    const webIdNode = rdf.namedNode(webId);
    
    console.log('\n=== Query ===');
    console.log('Subject:', webIdNode.value);
    console.log('Predicate:', providerTerm.value);
    
    const providerUri = store.anyValue(webIdNode, providerTerm);
    console.log('\n=== Result ===');
    console.log('Provider URI:', providerUri);
    console.log('Provider URI type:', typeof providerUri);
    
    // Also check what's in the store
    console.log('\n=== All oidcIssuer statements ===');
    const statements = store.match(null, providerTerm, null);
    statements.forEach(st => {
      console.log('  Subject:', st.subject.value);
      console.log('  Object:', st.object.value);
    });
    
    // Compare with token issuer
    const tokenIssuer = 'https://melvincarvalho.com/';
    console.log('\n=== Comparison ===');
    console.log('Token issuer:', tokenIssuer);
    console.log('Provider from profile:', providerUri);
    console.log('Match:', providerUri === tokenIssuer);
  })
  .catch(err => {
    console.error('Error:', err.message);
  });

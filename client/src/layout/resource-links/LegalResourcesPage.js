import React from 'react';
import { Container } from 'semantic-ui-react';
import PageLayout from '../components/PageLayout';
import ResourceLinks from './ResourceLinks';


export default () => (
  <PageLayout>
    <Container>
      <ResourceLinks
        title='Legal Resources'
        recordFilter={r => r.tags.some((tag) => (tag).match(/^legal-.+/i))}
        tagDisplayFilter={(tag) => (!tag.match(/^(legal-.+|us|us-states)$/i))}
      />
    </Container>
  </PageLayout>
)
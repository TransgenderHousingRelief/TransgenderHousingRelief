import React, { Component } from 'react';
import {
  Container,
  Header
} from 'semantic-ui-react';

import PageLayout from '../components/PageLayout';
import Search from '../../components/search/Search';
import SearchResults from '../../components/search/SearchResults';

class SearchPage extends Component {
  render() {
    return (
      <PageLayout>
        <Container>
          <Header as='h1'>Find Housing</Header>
          <Search />
          <SearchResults />
        </Container>
      </PageLayout>
    );
  }
}

export default SearchPage;

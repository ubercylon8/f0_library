import { Routes, Route } from 'react-router-dom';
import ErrorBoundary from './components/ErrorBoundary';
import Layout from './components/Layout';
import HomePage from './components/HomePage';
import TestDetailPage from './components/TestDetailPage';

function App() {
  return (
    <ErrorBoundary>
      <Layout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/test/:uuid" element={<TestDetailPage />} />
        </Routes>
      </Layout>
    </ErrorBoundary>
  );
}

export default App;

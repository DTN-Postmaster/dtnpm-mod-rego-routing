import { render } from 'preact';
import { RegoRoutingTab } from './RegoRoutingTab';

export { RegoRoutingTab };

const root = document.getElementById('app');
if (root) {
  render(<RegoRoutingTab />, root);
}

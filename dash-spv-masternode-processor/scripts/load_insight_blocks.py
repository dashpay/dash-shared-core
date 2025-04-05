import requests
import json
import argparse
from chain import Chain

parser = argparse.ArgumentParser(description='Script so useful.')
parser.add_argument("--root", type=int, default=0)
parser.add_argument("--head", type=int, default=1)
parser.add_argument("--step", type=int, default=1)
parser.add_argument("--chain", type=str, default='testnet')

args = parser.parse_args()

root = args.root
head = args.head
step = args.step
chain = Chain.from_string(args.chain)

blocks = []
for i in range(root, head, step):
    r = requests.get(f'https://{chain.api_base}/insight-api/block/{i}')
    block = r.json()
    block_hash = block["hash"]
    block_height  = block["height"]
    merkle_root = block["merkleroot"]
    print('MerkleBlock::reversed({}, "{}", "{}"), '.format(block_height, block_hash, merkle_root))
    blocks.append(block)

# with open('scripts/{}.json'.format(chain.name), 'w', encoding='utf-8') as f:
#     json.dump(blocks, f, ensure_ascii=False, indent=4)

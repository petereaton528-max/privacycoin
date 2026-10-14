"""Malformed metadata/progress cases; synthetic responses are not chain proof."""
import os,unittest
from unittest.mock import patch

@unittest.skipUnless(os.name=='posix','Private wallet runtime is POSIX')
class MetadataPagingTests(unittest.TestCase):
    def fake(self,malformed=None):
        anchor=dict(tip='f'*64,revision=1,instance='i',height=2)
        def rpc(port,command,**q):
            if command=='snapshot_id':return anchor
            if command=='orphan_images_page':
                value=dict(anchor,images=['c'*64],after='c'*64,done=True)
                if malformed=='image_order':value['images']=['c'*64,'b'*64];value['after']='b'*64
                if malformed=='image_progress':value['done']=False
                if malformed=='image_anchor':value['revision']=2
                return value
            if command=='history':
                offset=q['offset'];image='b'*64 if offset==1 else 'a'*64
                value=dict(anchor,records=[dict(transaction='00',id=image,coinbase=False,height=offset,images=[image])],next=offset+1)
                if offset==1:value.update(images=[],orphan_images=[],pool_ids=[],metadata_paged=True)
                if malformed=='history_progress':value['next']=offset
                return value
            raise AssertionError(command)
        return rpc
    def test_reconstructed_images_are_complete_sorted_and_history_is_private(self):
        from apps.network_v1.desktop_backend import c
        with patch.object(c.w,'rpc',side_effect=self.fake()):state=c.snapshot(1)
        try:
            self.assertEqual(state['images'],['a'*64,'b'*64]);self.assertEqual(state['orphan_images'],['c'*64]);self.assertEqual(len(state['chain']),2)
        finally:state['chain'].file.close()
    def test_nonprogress_unordered_or_changed_pages_fail_closed(self):
        from apps.network_v1.desktop_backend import c
        for case in ('image_order','image_progress','image_anchor','history_progress'):
            with self.subTest(case=case),patch.object(c.w,'rpc',side_effect=self.fake(case)):
                with self.assertRaisesRegex(ValueError,'chain or pool changed'):c.snapshot(1)

if __name__=='__main__':unittest.main()
